# Mapl-App-NVDs
The following application has different endpoints to retrieve and manage API vulnerabilities from the NATIONAL VULNERABILITIES DATABASE (NVD), NIST.  

For more information: https://nvd.nist.gov/developers/vulnerabilities

The database used is MongoDB, it could be run in a local machine or in several cloud services. 

The application is developed in Python using the FastAPI framework.  The application could be deployed in a Docker container too.

_____________________________________________________
### For the credentials file .env send me a message on discord: Luck547#7467
_____________________________________________________

# Pre requisites 
## For the local execution of the API, the following components are required:

    
     Python3: The language the Ap has been written.
     Mongo:  The Db chosen as the data platform tested locally, containerized and in the Cloud.

And all the pip libraries contained in requirements.txt file.

    pymongo
    fastapi
    requests
    uvicorn

For Docker execution, Docker Engine (and optionally Docker compose plugin) it's only needed, and the rest of components will be automatically added.


_____
_____
# Instructions for Installation

## 1.- Clone the Repo

Run the following command to clone the repository.

```bash
git clone https://github.com/Qubo-FNSD/Mapl-App-NVDs.git
```

Navigate to the ap directory with:

```bash
cd Mapl-App-NVDs
```

___
___

 


##  Depending on the excecution mode, (Locally or in Docker) follow the instruction below.


# Locally:


## 2.- Create a new virtual environment.


```bash
python3 -m venv venv
```

## 3.- Activate the virtual environment.

```bash
source venv/bin/activate      
```

It will look like this:

![Checkpoint](/screenshots/Screenshot1.png)

____    
Install all the libraries using pip install -r requirements.txt:


```bash
pip install pipreqs

&&

pipreqs
```

Run Mongo.

```bash

sudo systemctl enable mongod

# Or in Mac 

brew services start mongodb-community

```

Navegate to app folder.

```bash
cd app
```

Run Python script.
```bash
python3 main.py
```
Now you can continue testing from Postman (instructions below).



# Installation Docker

     For mac:
          [https://docs.docker.com/desktop/install/mac-install/](https://docs.docker.com/desktop/install/mac-install/)   
          

     For Windows:
          
          [https://docs.docker.com/desktop/install/windows-install/](https://docs.docker.com/desktop/install/windows-install/)
          
          
     For Ubuntu:
          
          [https://docs.docker.com/desktop/install/ubuntu/](https://docs.docker.com/desktop/install/ubuntu/)



And follow the instructions. To run the scripts, we need to run Docker first.


# Run the Docker Containers.

From Mapl-App folder, navigate to the app folder and run the Docker build and compose command.

```bash
cd app
```

```bash
docker-compose up -d
```



When stop the containers is needed, use:

```bash
docker-compose down
```

### Or without docker-compose, but with Docker over Docker run from Dockerfile:

```bash
docker network create -d bridge mapl-net
```

```bash
docker run -d --network mapl-net -p 8000:8000 -v mapl-vol --name mapl-api --label mapl mapl-api
```

```bash
docker run -d --network mapl-net  -p 27017:27017 -v mapl-vol --name mongodb --label mapl mongo:latest
```


___
___

# Endpoint details
___
1.- Endpoint that returns the vulnerabilities filtered by the keyword, saves their degree of severity and categorizes them with an open status.

Endpoint: http://localhost:8000/getVulns

Parameters:
-  myapikey
-  keyword
-  resultsperpage

___

2.- Endpoint that receives the IDs of fixed vulnerabilities. If the vulnerability is open, it updates it to fixed status. 

Endpoint: http://localhost:8000/postFixedVulns

Parameters:

- In the body, as raw JSON, the following scheme:

{
"IDS": 
[
{"ID": "CVE-2020-13254"},

{"ID": "CVE-2020-13596"}
]
}

___

3.- Endpoint that returns a list with the vulnerabilities pending correction (status other than fixed).

Endpoint: http://localhost:8000/getOpenVulns

Parameters:

- Without parameters.

___

4.- Endpoint that returns a total of vulnerabilities by degree of severity (status open).

Endpoint: http://localhost:8000/getTotalVulnsBySeverity

parameters:
- Without parameters.

___
___


# Postman usage


### To import the testing collection, use the file .json


![Postman Import step 1](/screenshots/postman02.png)

![Postman Import step 2](/screenshots/postman03.png)

![Postman Usage Endpoint 1](/screenshots/postman001.png)

![Postman Usage Endpoint 2](/screenshots/postman002.png)

![Postman Usage Endpoint 3](/screenshots/postman3.png)

![Postman Usage Endpoint 4](/screenshots/postman003.png)



## Developmental potential:


### Be connected

https://join.slack.com/t/mapl-alp-2022/shared_invite/zt-1exbwmwps-zE7NC~bKRPWOozkr20RH4g
