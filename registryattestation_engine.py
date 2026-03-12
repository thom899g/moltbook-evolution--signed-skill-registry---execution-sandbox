"""
Decentralized Attestation Engine for skill registry.
Implements cryptographic signing and transparency log integration.
"""
import subprocess
import json
import hashlib
import logging
from typing import Dict, Optional, List, Any
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, Field, validator
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

from config.firebase_config import firebase_manager

logger = logging.getLogger(__name__)

class SkillMetadata(BaseModel):
    """Skill metadata model with validation"""
    skill_id: str
    developer_id: str
    name: str
    version: str
    description: str
    container_digest: str  # OCI image digest
    declared_permissions: List[str] = Field(default_factory=list)
    resource_requirements: Dict[str, Any] = Field(default_factory=dict)
    github_repo: Optional[str] = None
    verified_developer: bool = False
    
    @validator('container_digest')
    def validate_digest(cls, v):
        """Validate OCI image digest format"""
        if not v.startswith('sha256:'):
            raise ValueError('Container digest must start with sha256:')
        if len(v) != 71:  # sha256: + 64 hex chars
            raise ValueError('Invalid digest length')
        return v
    
    @validator('declared_permissions')
    def validate_permissions(cls, v):
        """Validate permission strings"""
        allowed_permissions = {
            'file_read', 'file_write', 'network', 'process', 
            'environment', 'device', 'sys_admin'
        }
        for perm in v:
            if perm not in allowed_permissions:
                raise ValueError(f'Invalid permission: {perm}')
        return v

class AttestationEngine:
    """Engine for creating and verifying skill attestations"""
    
    def __init__(self, rekor_url: str = "https://rekor.sigstore.dev"):
        self.rekor_url = rekor_url
        self.db = firebase_manager.get_firestore()
        self.config = firebase_manager.config
    
    def _run_cosign_command(self, args: List[str]) -> subprocess.CompletedProcess:
        """Execute cosign command with error handling"""
        try:
            result = subprocess.run(
                ['cosign'] + args,
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode != 0:
                logger.error(f"Cosign command failed: {result.stderr}")
            return result
        except FileNotFoundError:
            logger.error("Cosign not installed. Please install from https://github.com/sigstore/cosign")
            raise
        except subprocess.TimeoutExpired:
            logger.error("Cosign command timed out")
            raise
    
    def sign_skill_container(self, container_ref: str, github_token: Optional[str] = None) -> Dict[str, str]:
        """
        Sign a skill container image using keyless signing via GitHub OIDC
        
        Args:
            container_ref: Docker image reference (e.g., ghcr.io/username/skill:latest)
            github_token: Optional GitHub token for private repos
            
        Returns:
            Dictionary with signing results
        """
        logger.info(f"Signing container: {container_ref}")
        
        # Build cosign arguments for keyless signing
        args = ["sign", container_ref]
        
        if github_token:
            args.extend(["--oidc-issuer", "https://token.actions.githubusercontent.com"])
        
        # Execute signing
        result = self._run_cosign_command(args)
        
        if result.returncode == 0:
            logger.info(f"Successfully signed {container_ref}")
            
            # Extract signature and digest from output
            # Cosign outputs to stdout with format: sha256:digest
            lines = result.stdout.strip().split('\n')
            signature_info = {}
            for line in lines:
                if line.startswith('sha256:'):
                    signature_info['digest'] = line
                    break
            
            return {
                "success": True,
                "digest": signature_info.get('digest', ''),
                "container_ref": container_ref,
                "timestamp": datetime.utcnow().isoformat()
            }
        else:
            logger.error(f"Failed to sign container: {result.stderr}")
            return {
                "success": False,
                "error": result.stderr,
                "container_ref": container_ref
            }
    
    def verify_skill_signature(self, container_ref: str, digest: str) -> bool:
        """Verify a skill container signature"""
        logger.info(f"Verifying signature for: {container_ref}")
        
        args = ["verify", container_ref, "--claim-digest", digest]
        result = self._run_cosign_command(args)
        
        if result.returncode == 0:
            logger.info(f"Signature verified for {container_ref}")
            return True
        else:
            logger.warning(f"Signature verification failed: {result.stderr}")
            return False
    
    def store_attestation(self, skill_metadata: SkillMetadata, 
                         signature_result: Dict[str, Any]) -> str:
        """
        Store attestation in Firestore and optionally publish to Rekor
        
        Args:
            skill_metadata: Validated skill metadata
            signature_result: Result from sign_skill_container
            
        Returns:
            Document ID of stored attestation
        """
        try:
            # Prepare attestation document
            attestation = {
                "skill_id": skill_metadata.skill_id,
                "developer_id": skill_metadata.developer_id,
                "metadata": skill_metadata.dict(),
                "signature": signature_result,
                "attestation_timestamp": datetime.utcnow(),
                "verified": signature_result.get("success", False),
                "rekor_entry_uuid": None
            }
            
            # Store in Firestore
            doc_ref = self.db.collection(self.config.attestations_collection).document()
            doc_ref.set(attestation)
            
            # Also update skills registry for discovery
            registry_doc = {
                **skill_metadata.dict(),
                "attestation_id": doc_ref.id,
                "last_updated": datetime.utcnow(),
                "attestation_status": "signed" if signature_result.get("success") else "failed"
            }
            
            self.db.collection(self.config.skills_registry_collection) \
                   .document(skill_metadata.skill_id) \
                   .set(registry_doc, merge=True)
            
            logger.info(f"Attestation stored with ID: {doc_ref.id}")
            
            # Optional: Publish to Rekor transparency log
            if signature_result.get("success"):
                try:
                    rekor_uuid = self._publish_to_rekor(skill_metadata, signature_result)
                    if rekor_uuid:
                        doc_ref.update({"rekor_entry_uuid": rekor_uuid})
                except Exception as e:
                    logger.warning(f"Failed to publish to Rekor: {str(e)}")
            
            return doc_ref.id
            
        except Exception as e:
            logger.error(f"Failed to store attestation: {str(e)}", exc_info=True)
            raise
    
    def _publish_to_rekor(self, skill_metadata: SkillMetadata, 
                         signature_result: Dict[str, Any]) -> Optional[str]:
        """Publish attestation to Rekor transparency log"""
        try:
            # Create Rekor entry
            entry = {
                "apiVersion": "0.0.1",
                "kind": "hashedrekord",
                "spec": {
                    "data": {
                        "hash": {
                            "algorithm": "sha256",
                            "value": signature_result["digest"].replace("sha256:", "")
                        }
                    },
                    "signature": {
                        "content": signature_result.get("signature", ""),
                        "publicKey": {
                            "content": ""  # Would be populated with actual key
                        }
                    }
                }
            }
            
            # Post to Rekor
            response = requests.post(
                f"{self.rekor_url}/api/v1/log/entries",
                json=entry,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 201:
                rekor_data = response.json()
                # Extract UUID from response
                for key in rekor_data.keys():
                    if key != "logIndex":
                        return key  # This is the UUID
                
            return None
            
        except requests.RequestException as e:
            logger.error(f"Rekor API error: {str(e)}")
            return None
    
    def verify_attestation_chain(self, skill_id: str) -> Dict[str, Any]:
        """Verify the complete attestation chain for a skill"""
        try:
            # Get attestation from Firestore
            attestation_doc = self.db.collection(self.config.attestations_collection) \
                .where("skill_id", "==", skill_id) \
                .order_by("attestation_timestamp", direction=firestore.Query.DESCENDING) \
                .limit(1) \
                .get()
            
            if not attestation_doc:
                return {"verified": False, "error": "No attestation found"}
            
            attestation = attestation_doc[0].to_dict()
            
            # Verify signature
            container_ref = attestation["metadata"]["container_digest"]
            digest = attestation["signature"]["digest"]
            signature_verified = self.verify_skill_signature(container_ref, digest)
            
            # Check Rekor entry if exists
            rekor_verified = False
            if attestation.get("rekor_entry_uuid"):
                try:
                    response = requests.get(
                        f"{self.rekor_url}/api/v1/log/entries/{attestation['rekor_entry_uuid']}"
                    )
                    rekor_verified = response.status_code == 200
                except requests.RequestException:
                    pass
            
            return {
                "verified": signature_verified and (rekor_verified or attestation["rekor_entry_uuid"] is None),
                "signature_verified": signature_verified,
                "rekor_verified": rekor_verified,
                "attestation_timestamp": attestation["attestation_timestamp"],
                "skill_metadata": attestation["metadata"]
            }