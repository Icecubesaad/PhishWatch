from fastapi import FastAPI
from pydantic import BaseModel
import pickle
import validators
from functions.feature_extraction import extract_features

app = FastAPI()

@app.get("/")
def read_root():
    return {"Hello": "World"}

class URL(BaseModel):
    url_name: str

@app.post("/model")
def model_predict(url: URL):
    print("request received ->",url.url_name)
    if not validators.url(url.url_name):
        return {"output": "URL is malformed. Please enter the right format", "success": False}
    else:
        model = pickle.load(open('../model/finalized_model.sav', 'rb'))
        features = extract_features(url.url_name)
        if features is None:
            return {"output": "Could not extract features from the URL. Please try again with a different URL.", "success": False}
        prediction = model.predict(features)
        print(prediction)
        if prediction==[0]:
            return {"output": "Legitimate URL", "success": True}
        else:
            return {"output": "Phishing URL", "success": True}
