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
from decouple import config

