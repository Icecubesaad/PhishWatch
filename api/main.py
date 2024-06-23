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
    url_name:str
@app.post("/model")
def model_predict(url:URL):
    # if the user didn't enter the right format or have the right format
    if not validators.url(url.url_name):
        return {"error":"URL is malformed. Please enter the right format"}
    else:
        # load the trained model using "pickle" module
        model = pickle.load(open('../model/finalized_model.sav','rb'))
        features = extract_features(url.url_name)
        if features==False:
            return {"output":"URL is phishing"}
        else:
            output = model.predict(features)
            if output == [0]:
                return {"output":"URL is not phishing"}
            else:
                return {"output":"URL is phishing"}

