
GOPATH=$(PWD)/.go

APPNAME=keygen

test: echo
	go test

build: echo compile

compile:
	go build main/$(APPNAME).go

run-test:
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
	go get -u "github.com/eyedeekay/wtfsshbbq"

install:
	install -m755 $(APPNAME) /usr/local/lib/ssh-leygen
	ln -sf /usr/local/lib/ssh-leygen /usr/local/bin/ssh-leygen

travis: build clean
