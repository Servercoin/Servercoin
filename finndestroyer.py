specialdata = ""
with open("Servercoindeployapp.py","r") as file:
 specialdata = file.read()
specialdata = specialdata.replace("proprosedblocks","proposedblocks")
with open("Servercoindeployapp.py","w") as file:
	file.write(str(specialdata))