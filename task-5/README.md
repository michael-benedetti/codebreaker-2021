# Task 5

For task 5 we are given a docker container tar file and are tasked to identify the email of the PANIC employee who maintains the image, URL of the repository cloned when the image runs, and the full path the malicious file present in the image.

Let's start by loading the image and observing some initial metadata:

```bash
$ docker load -i image.tar
0d1322ca4d27: Loading layer [==================================================>]  20.24MB/20.24MB
cb9eaf2af081: Loading layer [==================================================>]  376.4MB/376.4MB
6729bcd16589: Loading layer [==================================================>]  3.072kB/3.072kB
fcc79f0185a6: Loading layer [==================================================>]  3.584kB/3.584kB
8aac151e8501: Loading layer [==================================================>]  3.584kB/3.584kB
Loaded image: panic-nightly-test:latest

$ docker image history panic-nightly-test:latest --no-trunc
IMAGE                                                                     CREATED        CREATED BY
                                                                                SIZE      COMMENT
sha256:...   7 months ago   /bin/sh -c #(nop)  LABEL docker.cmd.build=docker build --no-cache=true --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') --build-arg VCS_REF=$(git log -n 1 --abbrev-commit --pretty='%H') .      0B
<missing>    7 months ago   /bin/sh -c #(nop)  LABEL org.opencontainers.image.author=Jamie Willis
<missing>    7 months ago   /bin/sh -c #(nop)  LABEL org.opencontainers.image.description=Build and tests container for PANIC. Runs nightly.                                                                                        0B
<missing>    7 months ago   /bin/sh -c #(nop)  LABEL org.opencontainers.image.title=PANIC Nightly Build and Test
<missing>    7 months ago   /bin/sh -c #(nop)  LABEL org.opencontainers.image.revision=be3d94bc8340cc6db649f0339b7be4abbf2539da
<missing>    7 months ago   /bin/sh -c #(nop)  LABEL org.opencontainers.image.created=2021-03-24T09:51:10Z
<missing>    7 months ago   /bin/sh -c #(nop)  LABEL maintainer=willis.jamie@panic.invalid
<missing>    7 months ago   /bin/sh -c #(nop)  ARG VCS_REF
<missing>    7 months ago   /bin/sh -c #(nop)  ARG BUILD_DATE
<missing>    7 months ago   /bin/sh -c #(nop)  CMD ["./build_test.sh"]
<missing>    7 months ago   /bin/sh -c chmod +x ./build_test.sh
<missing>    7 months ago   /bin/sh -c #(nop) ADD file:248489bf03b8d244e867792e720697b102a8ee86b5fbd0426cfb6f37d64b3279 in ./build_test.sh
<missing>    7 months ago   /bin/sh -c #(nop) WORKDIR /usr/local/src
<missing>    7 months ago   /bin/sh -c apk add     automake     glib-dev     gtk-doc     libtool     expat     expat-dev     gobject-introspection-dev     wget     autoconf     libgcc      libstdc++      gcc      g++      git   367MB
<missing>    7 months ago   /bin/sh -c #(nop)  CMD ["/bin/sh"]
<missing>    7 months ago
```

By running `docker image history` on our image, we are getting a listing of the image's layers.  The most recent layer is at the top, and we see the history of how the image was originally built.  We can see a couple interesting things: 

1. Right off the bat we have one of our answers, as the maintainer is listed as `willis.jamie@panic.invalid`.
2. The CMD that will run when the container is started is `/usr/local/src/build_test.sh`

Let's load up our container and take a look inside.

```bash
docker run -it panic-nightly-test sh
/usr/local/src #
```

We are now running our container and have been presented with a root shell.  Let's take a look at the startup script `build_test.sh`:

```bash
#!/bin/bash

git clone https://git-svr-39.prod.panic.invalid/hydraSquirrel/hydraSquirrel.git repo

cd /usr/local/src/repo

./autogen.sh

make -j 4 install

make check
```

The script clones a git repository, which is another one of our answers, runs a script from the repository, and then runs a couple make commands.  Unfortunately, after some initial exploration of the pcap data from task 1, we don't seem to be able to recover the git repo that was cloned, so we don't know what `autogen.sh` is doing, which makes determining the full path to the malicious file a bit more challenging.  

We know that there needs to be some execution flow that leads to executing the malware, however, and if we think carefully about what this script is doing, we will eventually land on the answer that the malicious file is `make`.  While we still don't know what `autogen.sh` is really doing, we can infer that it must be installing a malicious version of make, and then executing the malware immediately after installation.

We can get our third and final answer for this task by running `which make` which yields `/usr/bin/make`