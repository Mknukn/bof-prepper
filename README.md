# BOF-Prepper

BOF-Prepper is a semi-automated python script that I made for Tib3rius' Buffer Overflow Prep room in TryHackMe.

It automates the boring tasks such as changing the bad characters one by one, finding the EIP offset, and generally
anything to do with editing your current exploit before sending in the final reverse shell.

## Dependencies

BOF-Prepper relies on the pwntools library specifically the library which deals with cyclic pattern generation. You can
find them over here: [pwntools](https://github.com/Gallopsled/pwntools)

## Usage

The usage is pretty simple. It mimics the task at hand that you do and still needs input from the user.
You can start BOF-Prepper like this:

```

python3 bof-prepper.py -i [IP-Address] -p [port] -x [COMMAND]


```


## TODO

Add in a menu so we can focus on seperate tasks (e.g., maybe just use it for exploit purposes or fuzzing)

