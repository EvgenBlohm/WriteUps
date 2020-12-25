# How to run **elf** binaries on Mac OS

Most Reversing CTFs use either PE/ELF binaries which do not run nativly on Mac OS. One solution for this is to run a Linux/Windows based VM. However sometimes I'm just 
lazy and don't want to start a new VM. Another way to solve this problem is to use [karton](https://github.com/karton/karton).

## What's karton and how to use and install it

karton is basically a wrapper around docker where the binaries are executed and access is provided to the user. Before we can use it we need to create an image.

In my case I have a `ELF 64-bit LSB executable, x86-64` binary that I want to run on my Mac, so lets first install **karton** 
(in many cases I have just copy/pasted stuff from the offical [docs](https://karton.github.io/how-to-use.html))

To install karton we run the commands shown [here](https://karton.github.io/install.html)
On Mac we first need python 2.7 and docker. 
Then we run `pip install karton` and we are done.

Now to use a image we first need to create it. To do so I have created a directory called **karton_images**. To create a new image we run 
`karton image create <IMAGE_NAME> <PATH_TO_SAVE>` so in my case as I want to create a Ubuntu 20.4 image I have called the image ubuntu_20

## Configure the image

Running the last command creates a file called **definition.py** in <PATH_TO_SAVE>. This file holds the configuration about the image. A explanation of all values can be
found [here](https://github.com/karton/karton/blob/master/docs/props.md)

After all values are configured we can run `karton build <IMAGE_NAME>`
