FROM python:3-onbuild

MAINTAINER Thomas Sunde Nielsen

EXPOSE 41414

CMD [ "python", "./server.py" ]
