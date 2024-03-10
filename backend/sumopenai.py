import requests

API_URL = "https://api-inference.huggingface.co/models/MBZUAI/LaMini-Flan-T5-248M"
headers = {"Authorization": "Bearer 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"}

def query(payload):
	response = requests.post(API_URL, headers=headers, json=payload)
	return response.json()
	
output = query({
	"inputs": "write about neil arm strong",
})

print(output)