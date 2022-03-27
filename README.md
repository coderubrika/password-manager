## How to startup

1. Clone the template yourself and go into it `git clone https://github.com/coderubrika/python-startup.git && cd python-startup`
2. Create virtual environment
    - For Windows `python -m venv venv`
    - For Linux `python3 -m venv venv`
4. Activate virtual environment
    - For Windows `venv/Scripts/activate` or use `./venv_activation.bat`
    - For Linux `source venv/bin/activate`
3. 
    - Install dependencies on Windows `pip install -r requrements.txt` 
    - Install dependencies on Linux `pip3 install -r requrements.txt` 

- For VSCode you need install [Python extension](https://marketplace.visualstudio.com/items?itemName=ms-python.python).
- For JetBrains you need apply virtual environment in `File/Settings/Project/Project Interpreter/Show All/+/Existing Environment` choose your created environment.

## How to work with it

Template config set to run in **JetBrains** ideas and **VSCode**.

The template has several application launch points: **Development**, **Init**, **Production**, **Stage**, **Test**, **Sandbox**.

All endpoint .py files are located in the **startup** folder, start writing your code from there by selecting one of the endpoints

## *.env files

- Each of the endpoints has its own .env file with
your configuration, for example, to store network settings, database settings, and others.

- For example for **Production** mode this is **production.env** or for **Development** this is **development.env**.

- All **\*.env** files must be in the **env** folder

 - You can create **.env** files manually or use the **Init** endpoint, it has a script for creating **.env** files by default, and this also shows the meaning of the **Init** endpoint
 
 ## Uploading to your repository
 
You can simply fork the repository, or create own repository then run the following code in the terminal:
 
`git remote remove origin`
 
`git remote add origin <your repository link>`
 
`git branch -M main`
 
`git push -u origin main` 