
GOPATH=$(PWD)/.go

APPNAME=keygen

build: echo compile run clean

compile:
	go build main/$(APPNAME).go

run:
	./keygen
	./keygen -t rsa

clean:
	ls keys/
	rm -f keygen keys/*

echo:
	@echo "   $(APPNAME)"
	@echo $(GOPATH)
	find . -name '*.go' -exec gofmt -w {} \;

deps:
	go get -u "github.com/ScaleFT/sshkeys"
	go get -u "github.com/mikesmitty/edkey"

install:
	install -m755 $(APPNAME) /usr/local/lib/ssh-leygen
	ln -sf /usr/local/lib/ssh-leygen /usr/local/bin/ssh-leygen
