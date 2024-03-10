# Local Setup
- Clone the project
- Run `local_setup.sh`

# Local Development Run
- `local_run.sh` It will start the flask app in `development`. Suited for local development

# Replit run
- Go to shell and run
    `pip install --upgrade poetry`
- Click on `main.py` and click button run
- Sample project is at https://replit.com/@rishikvan/kanban-1
- The web app will be availabe at https://kanban-1.rishikvan.repl.co
- Format https://<replname>.<username>.repl.co

# Folder Structure

- `kanban1` is the  sqlite DB. It can be anywhere on the machine.
- `setup.sh` set up the virtualenv inside a local `.env` folder. Uses `pyproject.toml` and `poetry` to setup the project
- `local_run.sh`  Used to run the flask application in development mode
- `templates` - Default flask templates folder


```
├── kanban1.sqlite3 
├── local_run.sh
├── local_setup.sh
├── main.py
├── readme.md
├── requirements.txt  
├── api.yaml
└── templates
    ├── createcard.html
    └── editcard.html
    └── editlist.html
    └── home.html
    └── index.html
    └── list.html
    └── sign.html
    └── summary.html
```