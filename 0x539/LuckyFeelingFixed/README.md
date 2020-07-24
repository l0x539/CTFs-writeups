# Lucky Feeling (Fixed)

In this challenge we exploit how `mt_rand` works in some older php versions `5.x.x/7.0x`

[Link](http://challenges.0x0539.net:3003/)

## Exploiting

This challenge require couple tries using the next scripts
I solved it in a way, even that my first understanding was wrong, so i had a slight different approach, which is trying to sync attack time with the server, and try predict future values from `mt_rand`.

### `mt_rand` vulnerability

`mt_rand` through an error if `min > max` however that's prevented in our case and can't be exploited this way
`mt_rand` also return NULL if `max > PHP_INT_MAX` but that's also prevented

Type juggling could've been possible too since '>=' and '==' are used everywhere is this code, but it cannot be exploited in this challenge.

However, if we chack the response header 

```
HTTP/1.1 200 OK
Date: Fri, 24 Jul 2020 05:49:53 GMT
Server: Apache/2.4.10 (Debian)
X-Powered-By: PHP/5.6.31
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 398
Connection: close
Content-Type: text/html; charset=UTF-8
```

it's running `PHP/5.6.31`

* Playing with `mt_rand`

messing with `mt_rand` showed that when passing a large number close to `PHP_INT_MAX`

```php
$round = 9223372036854775806;
```


```php
php> var_dump(decbin(mt_rand(1,$round)));
string(63) "111101101110110001110101101000100000000000000000000000000000001"
```

As you can see first bits are not randomized

* `srand`:

if you solved the previous `Lucky Feeling` challenge you'll know that this can be predicted
```php
srand(time());
$rnd = rand();
```

* Partially Predicting `$rand &= mt_rand(1,$round)`

if you chose two intervals of n times, you'll notice that the random values can be predicted sometimes.

means that we can guess the values that are whether 0 or 1.

### Exploiting:

- using python3 [exploit.py](https://github.com/l0x539/CTFs-writeups/tree/master/0x539/LuckyFeelingFixed/exploit.py)

running the script:

```
$ python3 exploit.py 
This took: 0.5889356136322021 secondes
PHPSESSID 952b6844ba2df2432840125efbda4340
offset: 14401
stamp: 1595586503
Go predict => 1595586533
[R,]> 
```

- using [predict.php](https://github.com/l0x539/CTFs-writeups/tree/master/0x539/LuckyFeelingFixed/predict.php)

```php
$pred = 1595525213;  // predict variable
```

TBA

