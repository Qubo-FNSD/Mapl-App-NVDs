#!/usr/bin/python3
# encoding: utf-8

#   Mapl App. Endpoints API that manage vulns, CVEs, and Bases of Severities.

#   Modules and Python packages used.
import sys
from pymongo import MongoClient
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi import FastAPI, requests, Depends, HTTPException, status
from bson.json_util import dumps, loads
from typing import Optional, Dict
import pymongo.errors
import requests
import pathlib
import secrets
import uvicorn
import json
import os

#   Consts
mode_dropDB = "del"
status_success = "Success"
status_error = "Error"
status_warning = "Warning"
status_fixed = "fixed"

#   Connection to mongoDB with docker and locally
if os.environ.get('DOCKER_CONTAINER', False) == "Yes":
    try:
        client = MongoClient('mongodb://mongodb:27017/')
    except pymongo.errors.ServerSelectionTimeoutError as failed_db:
        print("Mongo client is down", failed_db)
        sys.exit(1)
else:
    try:
        client = MongoClient('localhost', 27017, serverSelectionTimeoutMS="10")
    except pymongo.errors.ServerSelectionTimeoutError as failed_db:
        print("Mongo client is down", failed_db)
        sys.exit(1)

db = client['Data']
collection = db['Coll']

#   Initializing API APP
app = FastAPI()

#   Initializing API APP Basic Security (user and pass for every endpoint)
security = HTTPBasic()


#   Root endpoint or Sandbox
@app.get("/")
def firstPayload():
    message_eng = "The following Endpoints are available: " \
                  "getVulns, postFixedVulns, getOpenVulns, getTotalVulnsBySeverity . " \
                  "You can reach them from everywhere. But these " \
                  "endpoints are protected. So, if you need to access them, " \
                  "please contact to whom give you this domain or look the documentation"

    message_spa = "Los siguientes parámetros están disponibles: getVulns, postFixedVulns, getOpenVulns, " \
                  "getTotalVulnsBySeverity. Puede acceder a ellos desde cualquier lugar. Pero estos parámetros " \
                  "están protegidos. Por lo tanto si necesita acceder a ellos, comuníquese con quien le proporcionó " \
                  "este dominio o consulte la documentación."

    return message_spa, message_eng


#   Defining authentication
def authentication(username, password):
    current_username_bytes = username.encode("utf8")
    correct_username_bytes = b"usuario"
    is_correct_username = secrets.compare_digest(
        current_username_bytes, correct_username_bytes
    )
    current_password_bytes = password.encode("utf8")
    correct_password_bytes = b"copy&pasteME-547"
    is_correct_password = secrets.compare_digest(
        current_password_bytes, correct_password_bytes
    )
    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="El usuario ingresado no existe",
            headers={"WWW-Authenticate": "Basic"},
        )
    return


# First endpoint which retrieve and consume vulns from the https://services.nvd.nist.gov/rest/json/cves/1.0/ API
@app.get("/getVulns")
# Automate paging and get all the vulns from the API

def retrieveVulns(keyword: Optional[str] = None, mode: Optional[str] = None, resultsperpage: Optional[int] = 500,
                  myapikey: Optional[str] = None, credentials: HTTPBasicCredentials = Depends(security)):
    authentication(credentials.username, credentials.password)
    total_vulns = []
    added_records = 0
    message = None
    status = None
    if mode == None:
        url = "https://services.nvd.nist.gov/rest/json/cves/1.0/?keyword=%s&resultsPerPage=%s&apiKey=%s&isExactMatch=true" % (
            keyword, resultsperpage, myapikey)
        data = requests.get(url)
        if data.status_code == 200:
            response_json = data.json()
            if "result" in response_json:
                status = status_success
                result = response_json["result"]["CVE_Items"]
                for item in result:
                    cve_db = db.collection.find_one({"ID": item["cve"]["CVE_data_meta"]["ID"]})
                    if cve_db == None:
                        vuln = None
                        if "baseMetricV3" in item["impact"]:
                            try:
                                db.collection.insert_one({
                                    "CVE_data_type": response_json["result"]["CVE_data_type"],
                                    "CVE_data_format": response_json["result"]["CVE_data_format"],
                                    "CVE_data_version": response_json["result"]["CVE_data_version"],
                                    "CVE_data_timestamp": response_json["result"]["CVE_data_timestamp"],
                                    "ID": item["cve"]["CVE_data_meta"]["ID"],
                                    "baseSeverity": item["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"],
                                    "status": "open"
                                })
                                added_records += 1
                                vuln = (item["cve"]["CVE_data_meta"]["ID"],
                                        item["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"])
                                total_vulns.append(vuln)
                            except pymongo.errors.ServerSelectionTimeoutError as failed_db:
                                print("Mongo client is down", failed_db)
                                sys.exit(1)
                        elif not item["impact"]:
                            try:
                                db.collection.insert_one({
                                    "CVE_data_type": response_json["result"]["CVE_data_type"],
                                    "CVE_data_format": response_json["result"]["CVE_data_format"],
                                    "CVE_data_version": response_json["result"]["CVE_data_version"],
                                    "CVE_data_timestamp": response_json["result"]["CVE_data_timestamp"],
                                    "ID": item["cve"]["CVE_data_meta"]["ID"],
                                    "baseSeverity": "None",
                                    "status": "open"
                                })
                                added_records += 1
                                vuln = (item["cve"]["CVE_data_meta"]["ID"], "None")
                                total_vulns.append(vuln)
                            except pymongo.errors.ServerSelectionTimeoutError as failed_db:
                                print("Mongo client is down", failed_db)
                                sys.exit(1)
                        else:

                            try:
                                db.collection.insert_one({
                                    "CVE_data_type": response_json["result"]["CVE_data_type"],
                                    "CVE_data_format": response_json["result"]["CVE_data_format"],
                                    "CVE_data_version": response_json["result"]["CVE_data_version"],
                                    "CVE_data_timestamp": response_json["result"]["CVE_data_timestamp"],
                                    "ID": item["cve"]["CVE_data_meta"]["ID"],
                                    "baseSeverity": item["impact"]["baseMetricV2"]["severity"],
                                    "status": "open"
                                })
                                added_records += 1
                                vuln = (item["cve"]["CVE_data_meta"]["ID"], item["impact"]["baseMetricV2"]["severity"])
                                total_vulns.append(vuln)
                            except pymongo.errors.ServerSelectionTimeoutError as failed_db:
                                print("Mongo client is down", failed_db)
                                sys.exit(1)
                message = "Database have been updated. %s records has been added" % added_records
            else:
                status = status_error
                message = data.json()

        else:
            status = status_error
            message = "Nist API Status code is %s" % data.status_code

    elif mode == mode_dropDB:  # Modo adicional,  documentar
        try:
            db.collection.drop()
            status = status_success
            message = "All CVE data has been removed from the database"
        except pymongo.errors.OperationFailure as failed_drop:
            status = status_error
            message = "The database have been not removed", failed_drop
    else:
        status = status_error
        message = "Mode %s is not defined" % mode

    json_total_vulns = json.dumps({"results": status, "message": message, "data": total_vulns})

    return json.loads(json_total_vulns.replace("'", '"'))


# Second endpoint which permit to change the CVE status from "open" to "fixed"

@app.post("/postFixedVulns", status_code=201)
def updateStatus(IDS: Dict, credentials: HTTPBasicCredentials = Depends(security)):
    authentication(credentials.username, credentials.password)
    message = None
    messages = []
    ids = (dict(IDS))
    if bool(IDS) == True:
        for id in ids["IDS"]:
            cve_db = db.collection.find_one({"ID": id["ID"]})
            if cve_db == None:
                status = status_error
                message = "Cve id %s does not exists in the database." % (id["ID"])
                messages.append(message)
            elif cve_db["status"] == status_fixed:
                status = status_warning
                message = "Cve id %s is already fixed." % (id["ID"])
                messages.append(message)
            else:
                filter: dict[str, Any] = {'_id': cve_db["_id"]}
                db.collection.update_one(filter, {"$set": {"status": "fixed"}})
                status = status_success
                message = "Cve id %s was fixed" % (id["ID"])
                messages.append(message)

        if bool(ids["IDS"]) == True:
            return_message = json.dumps({"results": status, "message": messages})
        else:
            return_message = json.dumps({"results": status_error, "message": "Incorrect body"})
    else:
        return_message = json.dumps({"results": status_error, "message": "Empty body"})

    return json.loads(return_message.replace("'", '"'))


#   Third endpoint which get all CVE saved in the DB that are not fixed (with an open status).
@app.get("/getOpenVulns")
def retrieveOpenVulns(credentials: HTTPBasicCredentials = Depends(security)):
    open_vulns = []
    authentication(credentials.username, credentials.password)
    open_vulns_db = db.collection.find({"status": "open"})
    if open_vulns_db == None:
        status = status_warning
        message = "There are not open vulnerabilities"
    else:
        open_vulns_list = loads(dumps(list(open_vulns_db)))
        open_vulns = [item['ID'] for item in open_vulns_list if item.get('ID')]
        status = status_success
        message = "%s vulnerabilities are not fixed." % (len(open_vulns))

    return_message = json.dumps({"results": status, "message": message, "data": open_vulns})
    return json.loads(return_message.replace("'", '"'))


# Last endpoint which shows the total vulns by severity.
@app.get("/getTotalVulnsBySeverity")
def countBySeverity(credentials: HTTPBasicCredentials = Depends(security)):
    authentication(credentials.username, credentials.password)
    cve_db = (db.collection.find({}))
    cve_list = loads(dumps(list(cve_db)))
    critical_count = len([item['baseSeverity'] for item in cve_list if item.get('baseSeverity') == "CRITICAL"])
    high_count = len([item['baseSeverity'] for item in cve_list if item.get('baseSeverity') == "HIGH"])
    medium_count = len([item['baseSeverity'] for item in cve_list if item.get('baseSeverity') == "MEDIUM"])
    low_count = len([item['baseSeverity'] for item in cve_list if item.get('baseSeverity') == "LOW"])
    none_count = len([item['baseSeverity'] for item in cve_list if item.get('baseSeverity') == ""])
    status = status_success
    message = "%s Vulnerabilities in total" % (medium_count + high_count + critical_count + low_count + none_count)
    return_message = json.dumps({"results": status, "message": message,
                                 "data": {"Critical": critical_count, "High": high_count, "Medium": medium_count,
                                          "Low": low_count, "None": none_count}})
    return json.loads(return_message.replace("'", '"'))


#   Initialize when  running locally

if __name__ == "__main__":
    #uvicorn.run("main:app", reload=True, port=8000, log_config=f"{pathlib.Path(__file__).parent.resolve()}/log.ini")
    uvicorn.run("main:app", reload=False, port=8000, log_config=f"{pathlib.Path(__file__).parent.resolve()}/log.ini")
