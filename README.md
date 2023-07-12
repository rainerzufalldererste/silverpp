  <a href="https://github.com/rainerzufalldererste/silverpp"><img src="https://raw.githubusercontent.com/rainerzufalldererste/silverpp/master/assets/logo.png" alt="silverpp" style="width: 404px; max-width: 80%"></a>
  <br>
-------

### What is silverpp?
- A lightweight dynamic user mode profiler for Windows x64.
- Extremely fast. Almost **no** slowdown of the profiled application.
- Command Line based.
- Written in C++.
- Extremely small and hackable.
- BSD Licensed.

### How to use silverpp with my application?
**You don't need to make any changes to your application!** 

Simply make sure it's built with debug symbols and run it through silverpp like this:
```batch
silverpp.exe <PATH_TO_YOUR_APPLICATION>
```

If you need to pass any arguments to your application run:
```batch
silverpp.exe <PATH_TO_YOUR_APPLICATION> --args these args will be passed to your application
```

After you've performed the operations you want to profile, simply close the application.

<img src="https://raw.githubusercontent.com/rainerzufalldererste/silverpp/master/assets/ss0.png" alt="silverpp - Activity Graph" style="width: 909px; max-width: 100%">

Now select the region you want to analyze.

<img src="https://raw.githubusercontent.com/rainerzufalldererste/silverpp/master/assets/ss1.png" alt="silverpp - Hot Functions" style="width: 543px; max-width: 100%">

Now select the function you want to profile.

<img src="https://raw.githubusercontent.com/rainerzufalldererste/silverpp/master/assets/ss2.png" alt="silverpp - Source & Disassembly" style="width: 1461px; max-width: 100%">

Browse through the source code with highlighted expensive lines & optional inline disassembly.

It's that simple.

### Storing / Loading Sessions.
Profiling sessions can be stored by simply adding `--store <session_filename>` to the command-line parameters. To load a stored session simply run

```batch
silverpp.exe <PATH_TO_YOUR_APPLICATION> --load <session_filename>
```

### How fast is fast?
The performance impact is very minor, since silverpp only suspends the thread it's currently examining. You'll still get lots of profiling samples because silverpp is immediately yielding the CPU as soon as it's done.

Here's a benchmark on [hypersonic-rle-kit - the fastest decoding run length compression for x64](https://github.com/rainerzufalldererste/hypersonic-rle-kit)</a>.

<img src="https://raw.githubusercontent.com/rainerzufalldererste/silverpp/master/assets/bargraph.png" alt="silverpp - Source & Disassembly" style="width: 366px; max-width: 80%">

As you can see, the performance impact is marginal at best.

I've you're not happy with the amount of samples you're getting you can switch to the `--favor-accuracy` mode, but be warned: It'll have a massive performance impact on your application but will retrieve about 4x the amount of samples.


### Does this suffer from the Visual Studio 2019 'No user code was running' issue?
No. If Visual Studio 2019 refuses to profile, you can still profile using silverpp. This is actually one of the reasons silverpp was originally created.