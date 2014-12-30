
gpws
===

A command-line password safe written in go
---

The basic idea comes from https://github.com/janlelis/pws but I wanted to try it in golang.

Usage
---

     gpws -h
     Usage of gpws:
       -add="": add Password Entry
       -delete="": delete Entry
       -file="Store": Password Store File
       -update="": update Entry

     Examples:
     List Entries:
     gpws

     Add Entry in MyPasswordStore:
     gpws -file MyPasswordStore -add entry

     Delete entry:
     gpws -delete entry

     Update entry:
     gpws -update entry

     Get password for entry into clipboard:
     gpws entry


Requirements
---

Unfortunately there seems no easy way to use clipboard with golang. Thats why you have to install _xsel_ or _xclip_ for linux.


