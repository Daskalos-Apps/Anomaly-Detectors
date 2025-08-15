#!/usr/bin/env python3
"""
Enhanced Anomaly Detection Engine
Extends original detector with HTTP path analysis features
Compatible with federated learning framework
"""

import os
import sys
import json
import logging
import numpy as np
import pandas as pd
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import tensorflow as tf
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.optimizers import Adam
from tensorflow.keras import regularizers

# Import original components for compatibility
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from preprocessor import Preprocessor
from model_manager import ModelManager
from http_feature_extractor import HTTPFeatureExtractor
from utils import setup_logging, load_config


class EnhancedAnomalyDetector:
    """
    Enhanced anomaly detector with HTTP path analysis
    Maintains compatibility with original FL framework
    """
    
    def __init__(self, config_path: str = None):
        """
        Initialize enhanced detector
        
        Args:
            config_path: Path to configuration file
        """
        self.config = load_config(config_path or 'config/detection_engine.conf')
        self.logger = setup_logging('EnhancedDetector', self.config.get('logging', {}))
        
        # Initialize components
        self.preprocessor = Preprocessor()
        self.http_extractor = HTTPFeatureExtractor()
        self.model_manager = ModelManager()
        
        # Model configuration (maintains original architecture)
        self.model_config = {
            'architecture': '64-64-output',
            'n_features': 31,  # 21 network + 10 HTTP
            'n_classes': 2,
            'learning_rate': 0.001,
            'dropout_rate': 0.2,
            'l2_regularization': 0.001
        }
        
        self.model = None
        self.scaler = None
        self.threshold = self.config.get('threshold', 0.4)
        
        self.logger.info("Enhanced Anomaly Detector initialized")
    
    def create_model(self) -> Sequential:
        """
        Create the DNN model (same architecture as original)
        
        Returns:
            Keras Sequential model
        """
        model = Sequential([
            Dense(64, 
                  input_shape=(self.model_config['n_features'],),
                  activation='relu',
                  kernel_regularizer=regularizers.l2(self.model_config['l2_regularization'])),
            Dropout(self.model_config['dropout_rate']),
            
            Dense(64,
                  activation='relu',
                  kernel_regularizer=regularizers.l2(self.model_config['l2_regularization'])),
            Dropout(self.model_config['dropout_rate']),
            
            Dense(self.model_config['n_classes'], activation='softmax')
        ])
        
        model.compile(
            optimizer=Adam(learning_rate=self.model_config['learning_rate']),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        self.logger.info(f"Created model with architecture: {self.model_config['architecture']}")
        return model
    
    def extract_features(self, data: pd.DataFrame) -> pd.DataFrame:
        """
        Extract both network and HTTP features
        
        Args:
            data: Raw log data
            
        Returns:
            DataFrame with all features
        """
        # Extract network features (original)
        network_features = self.preprocessor.extract_network_features(data)
        
        # Extract HTTP features (enhanced)
        http_features = self.http_extractor.extract_features(data)
        
        # Combine features
        all_features = pd.concat([network_features, http_features], axis=1)
        
        self.logger.debug(f"Extracted {len(all_features.columns)} total features")
        return all_features
    
    def preprocess_data(self, data: pd.DataFrame) -> np.ndarray:
        """
        Preprocess data for model input
        
        Args:
            data: Feature data
            
        Returns:
            Scaled numpy array
        """
        # Handle missing values
        data = data.fillna(0)
        
        # Handle infinite values
        data = data.replace([np.inf, -np.inf], 0)
        
        # Scale features
        if self.scaler is None:
            from sklearn.preprocessing import StandardScaler
            self.scaler = StandardScaler()
            scaled_data = self.scaler.fit_transform(data)
        else:
            scaled_data = self.scaler.transform(data)
        
        return scaled_data
    
    def train(self, 
              train_data: pd.DataFrame,
              train_labels: np.ndarray,
              validation_split: float = 0.2,
              epochs: int = 50,
              batch_size: int = 32) -> Dict:
        """
        Train the enhanced model
        
        Args:
            train_data: Training data
            train_labels: Training labels
            validation_split: Validation data ratio
            epochs: Number of training epochs
            batch_size: Batch size
            
        Returns:
            Training history
        """
        self.logger.info("Starting model training...")
        
        # Extract features
        features = self.extract_features(train_data)
        
        # Preprocess
        X = self.preprocess_data(features)
        y = train_labels
        
        # Create model
        self.model = self.create_model()
        
        # Train
        history = self.model.fit(
            X, y,
            validation_split=validation_split,
            epochs=epochs,
            batch_size=batch_size,
            callbacks=[
                tf.keras.callbacks.EarlyStopping(
                    monitor='val_loss',
                    patience=10,
                    restore_best_weights=True
                ),
                tf.keras.callbacks.ReduceLROnPlateau(
                    monitor='val_loss',
                    factor=0.5,
                    patience=5,
                    min_lr=0.00001
                )
            ],
            verbose=1
        )
        
        self.logger.info("Training completed")
        return history.history
    
    def predict(self, data: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """
        Make predictions on new data
        
        Args:
            data: Input data
            
        Returns:
            Tuple of (predictions, confidence scores)
        """
        if self.model is None:
            raise ValueError("Model not trained or loaded")
        
        # Extract features
        features = self.extract_features(data)
        
        # Preprocess
        X = self.preprocess_data(features)
        
        # Predict
        probabilities = self.model.predict(X, verbose=0)
        
        # Apply threshold
        predictions = (probabilities[:, 1] >= self.threshold).astype(int)
        confidence = probabilities[:, 1]
        
        return predictions, confidence
    
    def analyze_log(self, log_path: str, chunk_size: int = 1000) -> pd.DataFrame:
        """
        Analyze Apache/Nginx log file for anomalies
        
        Args:
            log_path: Path to log file
            chunk_size: Process in chunks for large files
            
        Returns:
            DataFrame with detection results
        """
        self.logger.info(f"Analyzing log file: {log_path}")
        
        results = []
        
        # Process in chunks for memory efficiency
        for chunk in pd.read_csv(log_path, chunksize=chunk_size, 
                                 sep=' ', header=None, 
                                 error_bad_lines=False):
            # Parse log entries
            parsed_chunk = self.preprocessor.parse_apache_logs(chunk)
            
            # Predict
            predictions, confidence = self.predict(parsed_chunk)
            
            # Add results
            parsed_chunk['is_threat'] = predictions
            parsed_chunk['confidence'] = confidence
            parsed_chunk['risk_level'] = pd.cut(
                confidence,
                bins=[0, 0.3, 0.6, 0.9, 1.0],
                labels=['Low', 'Medium', 'High', 'Critical']
            )
            
            results.append(parsed_chunk)
        
        # Combine results
        all_results = pd.concat(results, ignore_index=True)
        
        # Log summary
        threat_count = all_results['is_threat'].sum()
        total_count = len(all_results)
        self.logger.info(f"Analysis complete: {threat_count}/{total_count} threats detected")
        
        return all_results
    
    def save_model(self, path: str):
        """
        Save model and preprocessor
        
        Args:
            path: Directory to save model
        """
        if self.model is None:
            raise ValueError("No model to save")
        
        os.makedirs(path, exist_ok=True)
        
        # Save model
        model_path = os.path.join(path, 'enhanced_model.h5')
        self.model.save(model_path)
        
        # Save scaler
        import joblib
        scaler_path = os.path.join(path, 'scaler.pkl')
        joblib.dump(self.scaler, scaler_path)
        
        # Save configuration
        config_path = os.path.join(path, 'model_config.json')
        with open(config_path, 'w') as f:
            json.dump(self.model_config, f, indent=2)
        
        self.logger.info(f"Model saved to {path}")
    
    def load_model(self, path: str):
        """
        Load saved model
        
        Args:
            path: Directory containing saved model
        """
        # Load model
        model_path = os.path.join(path, 'enhanced_model.h5')
        self.model = load_model(model_path)
        
        # Load scaler
        import joblib
        scaler_path = os.path.join(path, 'scaler.pkl')
        self.scaler = joblib.load(scaler_path)
        
        # Load configuration
        config_path = os.path.join(path, 'model_config.json')
        with open(config_path, 'r') as f:
            self.model_config = json.load(f)
        
        self.logger.info(f"Model loaded from {path}")
    
    def get_feature_importance(self) -> pd.DataFrame:
        """
        Get feature importance from the model
        
        Returns:
            DataFrame with feature importance scores
        """
        if self.model is None:
            raise ValueError("Model not trained")
        
        # Get weights from first layer
        weights = self.model.layers[0].get_weights()[0]
        importance = np.abs(weights).mean(axis=1)
        
        # Get feature names
        network_features = self.preprocessor.get_feature_names()
        http_features = self.http_extractor.get_feature_names()
        all_features = network_features + http_features
        
        # Create DataFrame
        importance_df = pd.DataFrame({
            'feature': all_features[:len(importance)],
            'importance': importance
        }).sort_values('importance', ascending=False)
        
        return importance_df
    
    def evaluate(self, test_data: pd.DataFrame, test_labels: np.ndarray) -> Dict:
        """
        Evaluate model performance
        
        Args:
            test_data: Test data
            test_labels: Test labels
            
        Returns:
            Dictionary with evaluation metrics
        """
        from sklearn.metrics import (
            accuracy_score, precision_recall_fscore_support,
            confusion_matrix, roc_auc_score
        )
        
        # Predict
        predictions, confidence = self.predict(test_data)
        
        # Calculate metrics
        accuracy = accuracy_score(test_labels, predictions)
        precision, recall, f1, _ = precision_recall_fscore_support(
            test_labels, predictions, average='binary'
        )
        
        cm = confusion_matrix(test_labels, predictions)
        
        try:
            auc = roc_auc_score(test_labels, confidence)
        except:
            auc = 0
        
        metrics = {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1),
            'auc': float(auc),
            'confusion_matrix': cm.tolist()
        }
        
        self.logger.info(f"Evaluation: F1={f1:.3f}, Precision={precision:.3f}, Recall={recall:.3f}")
        
        return metrics


def main():
    """
    Main function for standalone execution
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced Anomaly Detector')
    parser.add_argument('--mode', choices=['train', 'detect', 'evaluate'],
                       required=True, help='Operation mode')
    parser.add_argument('--data', required=True, help='Path to data')
    parser.add_argument('--model', help='Path to model directory')
    parser.add_argument('--output', help='Output path')
    parser.add_argument('--config', help='Configuration file')
    
    args = parser.parse_args()
    
    # Initialize detector
    detector = EnhancedAnomalyDetector(args.config)
    
    if args.mode == 'train':
        # Load training data
        train_data = pd.read_csv(args.data)
        # Assume last column is label
        train_labels = train_data.iloc[:, -1].values
        train_data = train_data.iloc[:, :-1]
        
        # Train
        detector.train(train_data, train_labels)
        
        # Save model
        if args.model:
            detector.save_model(args.model)
    
    elif args.mode == 'detect':
        # Load model
        if args.model:
            detector.load_model(args.model)
        
        # Analyze log
        results = detector.analyze_log(args.data)
        
        # Save results
        if args.output:
            results.to_csv(args.output, index=False)
            print(f"Results saved to {args.output}")
    
    elif args.mode == 'evaluate':
        # Load model
        if args.model:
            detector.load_model(args.model)
        
        # Load test data
        test_data = pd.read_csv(args.data)
        test_labels = test_data.iloc[:, -1].values
        test_data = test_data.iloc[:, :-1]
        
        # Evaluate
        metrics = detector.evaluate(test_data, test_labels)
        
        # Print metrics
        print(json.dumps(metrics, indent=2))
        
        # Save metrics
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(metrics, f, indent=2)


if __name__ == "__main__":
    main()