/*

This file is part of RREAT, an Open Source Reverse Engineering Project.

RREAT is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

RREAT is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with RREAT.  If not, see <http://www.gnu.org/licenses/>.

*/
#include <windows.h>
#include <stdio.h>

int main()
{
    fclose(fopen("hello world!", "r"));
    return 0;
}
