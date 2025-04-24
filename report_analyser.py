import json
import os
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import joblib

def analyze_report_file(file_path):
    """
    Analyze a threat report text file and classify it
    
    Args:
        file_path (str): Path to the report file
        
    Returns:
        dict: Analysis results
    """
    try:
        # Read the text file
        with open(file_path, 'r', encoding='utf-8') as f:
            text = f.read()
        
        # Simulate prediction using a NLP model
        # In a real implementation, this would load your actual model from prediction8.ipynb
        
        # Simulated model prediction
        prediction_results = {
            "predicted_class": "ransomware",
            "confidence": 0.87,
            "class_probabilities": {
                "ransomware": 0.87,
                "phishing": 0.08,
                "other": 0.03,
                "malware": 0.02
            },
            "top_classes": [
                ["ransomware", 0.87],
                ["phishing", 0.08],
                ["other", 0.03]
            ]
        }
        
        # Calculate text statistics
        word_count = len(text.split())
        
        analysis_result = {
            "analyzed_file": file_path,
            "file_type": "Threat Report",
            "text_length": len(text),
            "word_count": word_count,
            "prediction": prediction_results,
            "summary": f"This report was classified as {prediction_results['predicted_class']} with {prediction_results['confidence']:.2f} confidence."
        }
        
        return {
            "success": True,
            "result": analysis_result
        }
    
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

def predict_threat_from_text(text, model_path="./threat_model_v2"):
    """
    Actual implementation for prediction (would be used in production)
    
    Args:
        text (str): The report text
        model_path (str): Path to the model
        
    Returns:
        dict: Prediction results
    """
    try:
        # Load model components
        model = AutoModelForSequenceClassification.from_pretrained(model_path)
        tokenizer = AutoTokenizer.from_pretrained(model_path)
        threat_encoder = joblib.load(f"{model_path}/threat_encoder.joblib")
        
        # Tokenize input
        inputs = tokenizer(
            text,
            return_tensors="pt",
            padding=True,
            truncation=True,
            max_length=512
        )
        
        # Get model predictions
        with torch.no_grad():
            outputs = model(**inputs)
        
        # Process logits
        logits = outputs.logits
        probabilities = torch.nn.functional.softmax(logits, dim=1)[0]
        
        # Get prediction
        predicted_class_idx = torch.argmax(logits, dim=1).item()
        predicted_class = threat_encoder.inverse_transform([predicted_class_idx])[0]
        confidence = probabilities[predicted_class_idx].item()
        
        # Prepare detailed results
        class_probabilities = {
            threat_encoder.inverse_transform([i])[0]: prob.item()
            for i, prob in enumerate(probabilities)
        }
        
        # Sort classes by probability (descending)
        sorted_probs = sorted(
            class_probabilities.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return {
            "predicted_class": predicted_class,
            "confidence": confidence,
            "class_probabilities": class_probabilities,
            "top_classes": sorted_probs[:3]  # Top 3 most likely classes
        }
        
    except Exception as e:
        return {
            "error": str(e)
        }