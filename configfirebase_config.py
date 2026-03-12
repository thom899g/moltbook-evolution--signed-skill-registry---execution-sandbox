"""
Firebase configuration and initialization for MOLTBOOK Evolution.
Centralized Firebase setup to ensure consistent authentication across all components.
"""
import os
import logging
from typing import Optional
from dataclasses import dataclass

import firebase_admin
from firebase_admin import credentials, firestore, initialize_app
from google.cloud import logging as google_logging
from google.cloud.firestore import Client as FirestoreClient

logger = logging.getLogger(__name__)

@dataclass
class FirebaseConfig:
    """Configuration for Firebase services"""
    project_id: str = os.getenv("FIREBASE_PROJECT_ID", "moltbook-evolution")
    credentials_path: str = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "")
    
    # Collection names
    skills_registry_collection: str = "skills_registry"
    attestations_collection: str = "attestations"
    trust_context_collection: str = "trust_context"
    telemetry_collection: str = "telemetry_stream"
    audit_log_collection: str = "audit_trail"
    
    # Default settings
    max_retries: int = 3
    timeout_seconds: int = 30

class FirebaseManager:
    """Singleton manager for Firebase services with error handling and retry logic"""
    
    _instance: Optional['FirebaseManager'] = None
    _initialized: bool = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not self._initialized:
            self.config = FirebaseConfig()
            self.app = None
            self.db: Optional[FirestoreClient] = None
            self.cloud_logging = None
            self._initialized = True
    
    def initialize(self) -> bool:
        """Initialize Firebase services with robust error handling"""
        try:
            if firebase_admin._apps:
                self.app = firebase_admin.get_app()
                logger.info("Using existing Firebase app")
            else:
                if self.config.credentials_path and os.path.exists(self.config.credentials_path):
                    cred = credentials.Certificate(self.config.credentials_path)
                    self.app = initialize_app(cred, {
                        'projectId': self.config.project_id,
                    })
                    logger.info("Firebase initialized with service account")
                else:
                    # Use application default credentials (for GCP environments)
                    self.app = initialize_app()
                    logger.info("Firebase initialized with application default credentials")
            
            # Initialize Firestore
            self.db = firestore.client(app=self.app)
            
            # Initialize Cloud Logging
            self.cloud_logging = google_logging.Client(project=self.config.project_id)
            
            logger.info(f"Firebase Manager initialized for project: {self.config.project_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Firebase: {str(e)}", exc_info=True)
            # Fallback to stdout logging if Firebase fails
            return False
    
    def get_firestore(self) -> FirestoreClient:
        """Get Firestore client with validation"""
        if not self.db:
            if not self.initialize():
                raise RuntimeError("Firestore initialization failed")
        return self.db
    
    def get_logger(self, name: str):
        """Get a Cloud Logging logger with fallback to stdout"""
        if self.cloud_logging:
            return self.cloud_logging.logger(name)
        else:
            # Return a stdout logger as fallback
            import sys
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
            logger = logging.getLogger(name)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
            return logger

# Global instance
firebase_manager = FirebaseManager()