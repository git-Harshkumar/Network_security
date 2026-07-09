import sys
import os

from dotenv import load_dotenv
load_dotenv()
mongo_db_url = os.getenv("MONGODB_URL_KEY")
print(mongo_db_url)
import pymongo
from networksecurity.exception.exception import NetworkSecurityException
from networksecurity.logging.logger import logging
from networksecurity.pipeline.training_pipeline import TrainingPipeline

from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, File, UploadFile, Request, Form
from uvicorn import run as app_run
from fastapi.responses import Response
from starlette.responses import RedirectResponse
import pandas as pd

from networksecurity.utils.main_utils.utils import load_object

from networksecurity.utils.ml_utils.model.estimator import NetworkModel


client = pymongo.MongoClient(mongo_db_url)

from networksecurity.constant.training_pipeline import DATA_INGESTION_COLLECTION_NAME
from networksecurity.constant.training_pipeline import DATA_INGESTION_DATABASE_NAME

database = client[DATA_INGESTION_DATABASE_NAME]
collection = database[DATA_INGESTION_COLLECTION_NAME]


app = FastAPI()
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


from fastapi.templating import Jinja2Templates
templates = Jinja2Templates(directory="./templates")

@app.get("/", tags=["authentication"])
async def index():
    return RedirectResponse(url="/dashboard")

@app.get("/dashboard")
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request, "result": None})

@app.post("/predict-single")
async def predict_single(request: Request):
    try:
        form_data = await request.form()
        feature_names = [
            "having_IP_Address", "URL_Length", "Shortining_Service",
            "having_At_Symbol", "double_slash_redirecting", "Prefix_Suffix",
            "having_Sub_Domain", "SSLfinal_State", "Domain_registeration_length",
            "Favicon", "port", "HTTPS_token", "Request_URL", "URL_of_Anchor",
            "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
            "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe",
            "age_of_domain", "DNSRecord", "web_traffic", "Page_Rank",
            "Google_Index", "Links_pointing_to_page", "Statistical_report"
        ]
        input_dict = {feat: int(form_data.get(feat, 1)) for feat in feature_names}
        df = pd.DataFrame([input_dict])

        preprocessor = load_object("final_model/preprocessor.pkl")
        final_model   = load_object("final_model/model.pkl")
        network_model = NetworkModel(preprocessor=preprocessor, model=final_model)
        y_pred = network_model.predict(df)
        raw_value = int(y_pred[0])

        label = "SAFE" if raw_value == 1 else "PHISHING"
        # Simple heuristic confidence based on how many features agree with the result
        safe_count  = sum(1 for v in input_dict.values() if v == 1)
        phish_count = sum(1 for v in input_dict.values() if v == -1)
        total = len(feature_names)
        if raw_value == 1:
            confidence = round((safe_count / total) * 100)
        else:
            confidence = round((phish_count / total) * 100)
        confidence = max(confidence, 55)  # floor so it never looks 0%

        result = {
            "label":      label,
            "raw":        raw_value,
            "confidence": confidence,
            "inputs":     {k: str(v) for k, v in input_dict.items()},
        }
        return templates.TemplateResponse("dashboard.html", {"request": request, "result": result})
    except Exception as e:
        raise NetworkSecurityException(e, sys)

@app.get("/train")
async def train_route():
    try:
        train_pipeline=TrainingPipeline()
        train_pipeline.run_pipeline()
        return Response("Training is successful")
    except Exception as e:
        raise NetworkSecurityException(e,sys)

@app.post("/predict")
async def predict_route(request: Request,file: UploadFile = File(...)):
    try:
        df=pd.read_csv(file.file)
        #print(df)
        preprocesor=load_object("final_model/preprocessor.pkl")
        final_model=load_object("final_model/model.pkl")
        network_model = NetworkModel(preprocessor=preprocesor,model=final_model)
        print(df.iloc[0])
        y_pred = network_model.predict(df)
        print(y_pred)
        df['predicted_column'] = y_pred
        print(df['predicted_column'])
        #df['predicted_column'].replace(-1, 0)
        #return df.to_json()
        os.makedirs('prediction_output', exist_ok=True)
        df.to_csv('prediction_output/output.csv')
        table_html = df.to_html(classes='table table-striped')
        #print(table_html)
        return templates.TemplateResponse("table.html", {"request": request, "table": table_html})
        
    except Exception as e:
            raise NetworkSecurityException(e,sys)    
    
if __name__=="__main__":
    app_run(app,host="0.0.0.0",port=8000)    