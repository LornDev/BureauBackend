from flask import Flask, request, jsonify, make_response
from flask_cors import CORS, cross_origin
from pymongo import MongoClient
from bson import ObjectId
import jwt
import datetime
from functools import wraps
import bcrypt

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'mysecret'

client = MongoClient("mongodb://localhost:27017")
db = client.bureau
users = db.users
projects = db.projects
documents = db.documents
keywords = db.keywords
blacklist = db.blacklist

##### APP LOGIC #####
#get userId by from token
def get_userId_by_token(token):
    tokenData = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
    user = users.find_one({'userName':tokenData['user']})
    if user is not None:
        return str(user['_id'])
    
#authentication wrapper
def jwt_required(func):
    @wraps(func)
    def jwt_required_wrapper(*args, **kwargs):
        if "Authorization" not in request.headers:
            return jsonify( {'message' : 'Token is missing'}), 401
        token = request.headers["Authorization"].split(" ")[1]
        if not token:
            return jsonify( {'message' : 'Token is missing'}), 401
        bl_token = blacklist.find_one({"token":token})
        if bl_token is not None:
            return make_response(jsonify( {'message' : 'Token has been cancelled'}), 401)
        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except: 
            return jsonify( {'message' : 'Token is invalid'}), 401
        return func(*args, **kwargs)
    return jwt_required_wrapper


#custom conversion for Projects, Documents, Keywords
#(mongodb .find() returns a cursor, this needs iterated through to extract the actual list of data)
def produceProjectList(data): 
    list = []
    for item in data:
        listItem = {
        "_id": str(item['_id']),
        "name": item["name"],
        "description": item["description"],
        }
        list.append(listItem)
    return list

def produceKeywordList(data): 
    list = []
    for item in data:
        listItem = {
        "_id": str(item['_id']),
        "scope": item["scope"],
        "names": item["names"],
        "brief": item["brief"],
        "contentPath": item['contentPath']
        }
        list.append(listItem)
    return list

def produceDocumentList(data): 
    list = []
    for item in data:
        listItem = {
        "_id": str(item['_id']),
        "projectId": item['projectId'],
        "position": item['position'],
        "name": item['name'],
        "keywords": item['keywords'],
        "contentPath": item['contentPath']
        }

        list.append(listItem)
    return list

#positions project documents in order
def positionDocuments(docList):
    docJson = []

    # using "position" field
    # extract chapters from docList
    # populate docJson with chapter documents, adding a "scenes" field to each
    # for each chapter, find all scenes and sort, populate chapter under "scenes" field with sorted scenes
    # return json object
    
    return docJson

#checks for all required information for adding/updating calls
#project
def requiredProjectInfoPresent(parsedRequest):
    if "userId" in parsedRequest and \
        "name" in parsedRequest and \
        "description" in parsedRequest:
        return True
    else: return False

#document
def requiredDocumentInfoPresent(parsedRequest):
    if "projectId" in parsedRequest and \
        "position" in parsedRequest and \
        "name" in parsedRequest and \
        "contentPath" in parsedRequest and \
        "keywords" in parsedRequest:
        return True
    else: return False

#keyword
def requiredKeywordInfoPresent(parsedRequest):
    if "userId" in parsedRequest and \
        "scope" in parsedRequest and \
        "names" in parsedRequest and \
        "contentPath" in parsedRequest and \
        "brief" in parsedRequest:
        return True
    else: return False


#
#
#

##### API #####

#test
@app.route("/api/v1/hi", methods=["GET"])
def get():
    return make_response( jsonify("Hii!!!"), 200 )

#
#
#

## USER AND AUTHENTICATION API 
#login
@app.route('/api/v1/login', methods=['GET'])
def login():
    auth = request.authorization
    if auth:
        user = users.find_one( {'userName':auth.username } )
        if user is not None and bcrypt.checkpw(bytes(auth.password, 'UTF-8'), user["userHash"]):
            token = jwt.encode( {'user' : auth.username, 'exp' : datetime.datetime.now() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
            return make_response(jsonify( {'token':token}), 200)
        else:
            return make_response(jsonify( {'message':'Invalid username or password'}), 401) 
    return make_response(jsonify({'message':'Authentication required'}), 401)

#logout
@app.route('/api/v1/logout', methods=["GET"])
@jwt_required
def logout():
    token = request.headers["Authorization"].split(" ")[1]
    blacklist.insert_one({"token":token})
    return make_response(jsonify( {'message' : 'Logout successful'}), 200)

#add user
@app.route("/api/v1/users", methods=["POST"])
@cross_origin(allow_headers=['Content-Type'])
def add_user():
    parsedRequest = request.json 
    if "userName" in parsedRequest and "userHash" in parsedRequest:
       new_user = { "userName" : parsedRequest["userName"], "userHash" : bytes(parsedRequest["userHash"], 'utf-8') }
       new_user["email"] = parsedRequest["email"]
       new_user["userHash"] = bcrypt.hashpw(new_user["userHash"], bcrypt.gensalt())

       new_user_id = users.insert_one(new_user)
       return make_response( jsonify( {"UserID": str(new_user_id.inserted_id)} ), 201)
    else: return make_response( jsonify( {"error":"Unprocessible entry: Missing fields"} ), 422)

#delete user
@app.route("/api/v1/users/<string:id>", methods=["DELETE"])
@jwt_required
def delete_user_by_id(id):
    # should delete all associated documents, keywords and projects first
    # then
    result = users.delete_one({'_id':ObjectId(id)})
    if result.deleted_count == 1: 
        return make_response( jsonify({}), 204 )
    else: return make_response( jsonify( {"error" : "Invalid user ID"} ), 404 )
    
#
#
#

## PROJECT API
#all projects by user
@app.route("/api/v1/projects", methods=["GET"])
@jwt_required
def get_projects_by_user():
    token = request.headers["Authorization"].split(" ")[1]
    userId =  get_userId_by_token(token)
    data_to_return = produceProjectList(projects.find( {"userId":userId}))
    return make_response( jsonify(data_to_return), 200 )

#project by id
@app.route("/api/v1/projects/<string:id>", methods=["GET"])
def get_project_by_id(id):
    project = projects.find_one({'_id':ObjectId(id)})
    if project is not None: 
        project['_id'] = str(project['_id'])
        return make_response( jsonify( project ), 200 )
    else: return make_response( jsonify( {"error" : "Invalid project ID"} ), 404 )

#add project
@app.route("/api/v1/projects", methods=["POST", "OPTIONS"])
@cross_origin(allow_headers=['Content-Type'])
@jwt_required
def add_project():
    parsedRequest = request.json
    token = request.headers["Authorization"].split(" ")[1]
    userId =  get_userId_by_token(token)
    if requiredProjectInfoPresent(parsedRequest):
        new_project = { 
            "userId" : userId, 
            "name" : parsedRequest["name"],
            "description" : parsedRequest["description"]
        }

        new_project_id = projects.insert_one(new_project)
        new_project_link = "http://localhost:5000/api/v1/projects/" + str(new_project_id.inserted_id)
        return make_response( jsonify( {"url": new_project_link} ), 201)
    else: return make_response( jsonify( {"error":"Unprocessible entry: Missing fields"} ), 422)

#update project
@app.route("/api/v1/projects/<string:id>", methods=["PUT"])
@cross_origin(allow_headers=['Content-Type'])
@jwt_required
def update_project(id):
    parsedRequest = request.json
    print(parsedRequest) 
    if requiredProjectInfoPresent(parsedRequest):
        updated_project = { 
            "name" : parsedRequest["name"],
            "description" : parsedRequest["description"]
        }

        projects.update_one({ "_id": ObjectId(id) }, { "$set": updated_project })
        updated_project_link = "http://localhost:5000/api/v1/projects/" + id
        return make_response( jsonify( {"url": updated_project_link} ), 200)
    else: return make_response( jsonify( {"error":"Unprocessible entry: Missing fields"} ), 422)

#delete project
@app.route("/api/v1/users/<string:id>", methods=["DELETE"])
@jwt_required
def delete_project_by_id(id):
    # all associated keywords/documents should be deleted BEFORE deleting project
    # get all keywords in scope of project
    # get all documents in project
    # for loops to delete all documents and keywords

    # then delete project:
    # result = projects.delete_one({'_id':ObjectId(id)})
    # if result.deleted_count == 1: 
    #     return make_response( jsonify({}), 204 )
    # else: return make_response( jsonify( {"error" : "Invalid project ID"} ), 404 )
    
    #placeholder
    return 0

   
#
#
#

## DOCUMENT API
#all documents for project
@app.route("/api/v1/documents/project/<string:id>", methods=["GET"])
@jwt_required
def get_documents_by_project(id):
    data_to_return = produceDocumentList(documents.find( {"projectId":id}))
    # data_to_return = positionDocuments(data_to_return)
    return make_response( jsonify(data_to_return), 200 )

#all documents containing keyword
@app.route("/api/v1/documents/keyword/<string:id>", methods=["GET"])
@jwt_required
def get_documents_by_keyword(id):
    data_to_return = produceDocumentList(documents.find( {"keywords":id}))
    return make_response( jsonify(data_to_return), 200 )

#document by id
@app.route("/api/v1/documents/<string:id>", methods=["GET"])
def get_document_by_id(id):
    document = documents.find_one({'_id':ObjectId(id)})
    if document is not None: 
        document['_id'] = str(document['_id'])
        return make_response( jsonify( document ), 200 )
    else: return make_response( jsonify( {"error" : "Invalid document ID"} ), 404 )

#add document
@app.route("/api/v1/documents/project/<string:projectId>", methods=["POST", "OPTIONS"])
@cross_origin(allow_headers=['Content-Type'])
@jwt_required
def add_document(projectId):
    parsedRequest = request.json
    if requiredDocumentInfoPresent(parsedRequest):
        new_document = { 
            "projectId" : projectId, 
            "name" : parsedRequest["name"],
            "position" : parsedRequest["position"],
            "keywords" : parsedRequest["keywords"],
            "contentPath" : parsedRequest["contentPath"]
        }

        new_document_id = documents.insert_one(new_document)
        new_document_link = "http://localhost:5000/api/v1/documents/" + str(new_document_id.inserted_id)

        # use new_document_id.inserted_id as a new file name
        # create this new file under "files/documents"

        return make_response( jsonify( {"url": new_document_link} ), 201)
    else: return make_response( jsonify( {"error":"Unprocessible entry: Missing fields"} ), 422)

#update document
@app.route("/api/v1/documents/<string:id>", methods=["PUT"])
@cross_origin(allow_headers=['Content-Type'])
@jwt_required
def update_document(id):
    parsedRequest = request.json
    print(parsedRequest) 
    if requiredDocumentInfoPresent(parsedRequest):
        updated_document = { 
            "name" : parsedRequest["name"],
            "position" : parsedRequest["position"],
            "keywords" : parsedRequest["keywords"],
            "contentPath" : parsedRequest["contentPath"]
        }

        documents.update_one({ "_id": ObjectId(id) }, { "$set": updated_document })
        updated_document_link = "http://localhost:5000/api/v1/documents/" + id
        return make_response( jsonify( {"url": updated_document_link} ), 200)
    else: return make_response( jsonify( {"error":"Unprocessible entry: Missing fields"} ), 422)

#delete document
@app.route("/api/v1/users/<string:id>", methods=["DELETE"])
@jwt_required
def delete_document_by_id(id):
    # delete document's associated rich text file first
    # then delete project:
    # result = documents.delete_one({'_id':ObjectId(id)})
    # if result.deleted_count == 1: 
    #     return make_response( jsonify({}), 204 )
    # else: return make_response( jsonify( {"error" : "Invalid document ID"} ), 404 )
    
    #placeholder
    return 0

#
#
#

## KEYWORD API
#all keywords by user
@app.route("/api/v1/keywords", methods=["GET"])
@jwt_required
def get_keywords_by_user():
    token = request.headers["Authorization"].split(" ")[1]
    userId =  get_userId_by_token(token)
    data_to_return = produceKeywordList(keywords.find( {"userId":userId}))
    return make_response( jsonify(data_to_return), 200 )

#all keywords scoped by project (or global if no id given)
@app.route("/api/v1/keywords/scoped", defaults={'id': ""}, methods=["GET"])
@app.route("/api/v1/keywords/scoped/<string:id>", methods=["GET"])
@jwt_required
def get_keywords_by_scope(id):
    token = request.headers["Authorization"].split(" ")[1]
    userId =  get_userId_by_token(token)
    data_to_return = produceKeywordList(keywords.find({"userId":userId, "scope":id}))
    return make_response( jsonify(data_to_return), 200 )

#keyword by id
@app.route("/api/v1/keywords/<string:id>", methods=["GET"])
def get_keyword_by_id(id):
    keyword = keywords.find_one({'_id':ObjectId(id)})
    if keyword is not None: 
        keyword['_id'] = str(keyword['_id'])
        return make_response( jsonify( keyword ), 200 )
    else: return make_response( jsonify( {"error" : "Invalid keyword ID"} ), 404 )

#add keyword
@app.route("/api/v1/keywords", methods=["POST", "OPTIONS"])
@cross_origin(allow_headers=['Content-Type'])
@jwt_required
def add_keyword():
    parsedRequest = request.json
    token = request.headers["Authorization"].split(" ")[1]
    userId =  get_userId_by_token(token)
    if requiredKeywordInfoPresent(parsedRequest):
        new_keyword = { 
            "userId" : userId, 
            "scope" : parsedRequest["scope"],
            "names" : parsedRequest["names"],
            "brief" : parsedRequest["brief"],
            "contentPath" : parsedRequest["contentPath"]
        }

        new_keyword_id = keywords.insert_one(new_keyword)
        new_keyword_link = "http://localhost:5000/api/v1/keywords/" + str(new_keyword_id.inserted_id)
        
        # use new_keyword_id.inserted_id as a new file name
        # create this new file under "files/keywords"

        return make_response( jsonify( {"url": new_keyword_link} ), 201)
    else: return make_response( jsonify( {"error":"Unprocessible entry: Missing fields"} ), 422)

#update keyword
@app.route("/api/v1/keywords/<string:id>", methods=["PUT"])
@cross_origin(allow_headers=['Content-Type'])
@jwt_required
def update_keyword(id):
    parsedRequest = request.json
    token = request.headers["Authorization"].split(" ")[1]
    userId =  get_userId_by_token(token)
    print(parsedRequest) 
    if requiredKeywordInfoPresent(parsedRequest):
        updated_keyword = { 
            "userId" : userId, 
            "scope" : parsedRequest["scope"],
            "names" : parsedRequest["names"],
            "brief" : parsedRequest["brief"],
            "contentPath" : parsedRequest["contentPath"]
        }

        keywords.update_one({ "_id": ObjectId(id) }, { "$set": updated_keyword })
        updated_keyword_link = "http://localhost:5000/api/v1/keywords/" + id
        return make_response( jsonify( {"url": updated_keyword_link} ), 200)
    else: return make_response( jsonify( {"error":"Unprocessible entry: Missing fields"} ), 422)

#delete keyword
@app.route("/api/v1/users/<string:id>", methods=["DELETE"])
@jwt_required
def delete_keyword_by_id(id):
    # get documents containing keyword
    # remove instances of keyword from documents 
    # delete associated keyword's associated text file

    # then delete keyword:
    # result = keywords.delete_one({'_id':ObjectId(id)})
    # if result.deleted_count == 1: 
    #     return make_response( jsonify({}), 204 )
    # else: return make_response( jsonify( {"error" : "Invalid keyword ID"} ), 404 )
    
    #placeholder
    return 0
   
#
#
#

if __name__ == "__main__":
    app.run(debug=True)