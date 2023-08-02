## Микросервис обертка над nmap

Позволяет выполнить сканирование хостов при помощи скрипта https://github.com/vulnersCom/nmap-vulners

### Установка

     git clone https://github.com/qwertyqq2/microservnmap



Предварительно необходимо установить nmap

### Запуск

     make build
     ./main



### Тестирование

##### Запуск тестов:

     make test

При тестах сканируются хосты: localhost, scanme.nmap.org. Сканирование может происходить долго



##### Запуск линтера:
Проверьте установлен ли линтер golint

Проверьте наличие BIN_DIR в PATH или настройте его:

     export GOPATH=$HOME/go
     export PATH=$PATH:$GOPATH/bin
     export PATH=$PATH:$GOROOT/bin


Запуск линтера:

     make linter

#### Отправка запросов
Тестирование запросов можно выполнить при помощи программы Evans

     evans proto/serv.proto -p 8000
     call CheckVuln






 