FROM mojalaxy/mojo-24.2.0-c2427bc5-release

RUN apt update -y && apt install -y socat

RUN chmod -R a+rwX /root
ENV MOJO_PYTHON_LIBRARY=/opt/conda/lib

WORKDIR /opt
ADD * e /opt/
ADD */*.py /opt/src/

RUN head -c 60 /dev/urandom > /secret.key
RUN adduser --no-create-home --disabled-password --gecos "" user
USER user

#CMD ["/opt/e"]
EXPOSE 1337
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/opt/e"]
