start : database.db globalsalt.txt
	export FLASK_ENV=development
	pipenv run flask run

database.db :
	pipenv run python make_database.py

globalsalt.txt :
	pipenv run python generate_globalsalt.py
