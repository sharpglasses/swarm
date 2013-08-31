#!/usr/bin/env node

/*-
 * Copyright (c) 2013 Masayoshi Mizutani <mizutani@sfc.wide.ad.jp>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

var fs = require('fs');
var spawn = require('child_process').spawn;

var default_conf = './tools/build.json';
var arg = process.argv[2];
var conf = JSON.parse (fs.readFileSync ((arg !== undefined) ? arg : default_conf));


function set_trigger (conf) {
  for (var d in conf['file_list']) {
    new function () {
      var dir_name = d;
      fs.readdir (d, function (err, files) {
        var regex_list = conf['file_list'][dir_name];
        for (var c = 0; c < files.length; c++) {
          regex_list.forEach (function (rgx_ptn) {
            rgx = new RegExp (rgx_ptn);
            if (files[c].match (rgx)) {
              var file = dir_name + '/' + files[c];
              console.log ('target: ' + file);
              fs.watchFile(file, { presistent: true, interval: 1000},
                           function(curr, prev) {
                             run_build (conf, file, curr, prev);
                           });
            }
          });
        }
      });
    }
  }

  run_build (conf, "INIT");
}


if (conf.forEach === undefined) {
  if (conf.enable !== 0) {
    set_trigger (conf);
  }
}
else {
  conf.forEach (function (c) {
    if (c.enable !== 0) {
      set_trigger (c);
    }
  });
}


function run_build(conf, file, curr, prev) {
  console.log("# -- changed: " + file + ' run: ' + conf['build_command']);

  var stdout_buffer = '';
  var stderr_buffer = '';
  var args = [];
  conf.build_args.forEach (function (v) {
    args.push (v === '$TARGET' ? file : v);
  });
  var mk = spawn(conf.build_command, args);

  mk.stdout.on('data', function(data) {
    stdout_buffer += data;
  });
  mk.stderr.on('data', function(data) {
    stderr_buffer += data;
  });

  mk.on('exit', function (code) {
    if (code != 0) {
      console.log ('--------- build error ------------------');
      console.log ('return code:' + code);
      process.stdout.write (stdout_buffer);
      process.stderr.write (stderr_buffer);
      console.log ('========= build error ==================');
    }
    else {
      console.log("# -- build complete!");
    }
  });
}


