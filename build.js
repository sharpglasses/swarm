[
  {"build_command": "./waf",
   "build_args":  [],
   "file_list": {"src":  ["^[A-Za-z0-9].*\\.(cc|h)"],
                 "src/proto": ["^[A-Za-z0-9].*\\.(cc|h)"],
                 "test": ["^[A-Za-z0-9].*\\.(cc|h)"]
                }
  },
  {"build_command": "./build/my_test",
   "build_args":  [],
   "file_list": {"build": ["my_test"]}
  }
]
 
