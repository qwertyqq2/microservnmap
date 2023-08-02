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



##### Запуск линтера(убедитесь, что установлен golangci-lint):

     make linter




 