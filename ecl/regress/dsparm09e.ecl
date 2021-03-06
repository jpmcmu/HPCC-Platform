/*##############################################################################

    HPCC SYSTEMS software Copyright (C) 2012 HPCC Systems®.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
############################################################################## */

// test: more than one level of dataset passing (w/ mapping)

ds := dataset('ds', {String10 first_name; string20 last_name; }, FLAT);

dataset f(virtual dataset({String10 name}) d) := d(name = 'fred');

dataset g(virtual dataset({String10 name2}) d) := d(name2='tom');

ds1 := f(ds{name:=first_name;});
ds2 := g(ds1{name2:=last_name;});

ct1 := output(ds2);

ct1;
