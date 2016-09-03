# Docs 
http://flask.pocoo.org/docs/0.11/quickstart/#a-minimal-application
http://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-i-hello-world
http://blog.miguelgrinberg.com/post/designing-a-restful-api-with-python-and-flask
http://blog.luisrei.com/articles/flaskrest.html

# Infos lors de la mise en place

1/
	Lors de l'utilisation de la pki en mode API, il faudra commenter ceci:

	l. 120         # calling signal handler
	l. 121         signal.signal(signal.SIGINT, self.sigint_handler

	En effet Flask refuse de gerer le SIGIT dans un thread.(quand le debugger est actif)

2/

