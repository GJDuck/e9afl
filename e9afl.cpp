/*
 *        ___    _    _____ _     
 *   ___ / _ \  / \  |  ___| |    
 *  / _ \ (_) |/ _ \ | |_  | |    
 * |  __/\__, / ___ \|  _| | |___ 
 *  \___|  /_/_/   \_\_|   |_____|
 * 
 * Copyright (C) 2021 National University of Singapore
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <climits>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <getopt.h>
#include <libgen.h>
#include <unistd.h>

#include <string>

enum Option
{
    OPTION_OBLOCK,
    OPTION_OSELECT,
    OPTION_DEBUG,
    OPTION_OUTPUT,
    OPTION_HELP
};

enum Value
{
    VALUE_NEVER,
    VALUE_DEFAULT,
    VALUE_ALWAYS
};

static bool option_is_tty = false;

/*
 * Report an error and exit.
 */
void __attribute__((noreturn)) error(const char *msg, ...)
{
    fprintf(stderr, "%serror%s  : ",
        (option_is_tty? "\33[31m": ""),
        (option_is_tty? "\33[0m" : ""));
    va_list ap;
    va_start(ap, msg);
    vfprintf(stderr, msg, ap);
    va_end(ap);
    putc('\n', stderr);
    exit(EXIT_FAILURE);
}

/*
 * Get the executable path.
 */
static void getExePath(std::string &path)
{
    char buf[PATH_MAX+1];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf)-1);
    if (len < 0 || len > sizeof(buf)-1)
        error("failed to read executable path: %s", strerror(errno));
    buf[len] = '\0';
    char *dir = dirname(buf);
    path += dir;
}

/*
 * Parse a value.
 */
static Value parseValue(const char *str)
{
    if (strcmp(str, "never") == 0)
        return VALUE_NEVER;
    else if (strcmp(str, "default") == 0)
        return VALUE_DEFAULT;
    else if (strcmp(str, "always") == 0)
        return VALUE_ALWAYS;
    error("failed to parse value \"%s\"; expected one of "
        "{never, default, always}", str);
}

/*
 * Value to string.
 */
static const char *getValue(Value value)
{
    switch (value)
    {
        case VALUE_NEVER:
            return "never";
        case VALUE_DEFAULT:
            return "default";
        case VALUE_ALWAYS:
            return "always";
    }
}

/*
 * Main.
 */
int main(int argc, char **argv)
{
    // Parse options:
    Value option_Oblock  = VALUE_DEFAULT,
          option_Oselect = VALUE_DEFAULT;
    bool option_debug = false;
    option_is_tty = isatty(STDERR_FILENO);
    char *option_output = nullptr;
    static const struct option long_options[] =
    {
        {"Oblock",  required_argument, nullptr, OPTION_OBLOCK},
        {"Oselect", required_argument, nullptr, OPTION_OSELECT},
        {"debug",   no_argument,       nullptr, OPTION_DEBUG},
        {"help",    no_argument,       nullptr, OPTION_HELP},
        {nullptr,   no_argument,       nullptr, 0}
    };
    while (true)
    {
        int idx;
        int opt = getopt_long_only(argc, argv, "d:o", long_options, &idx);
        if (opt < 0)
            break;
        switch (opt)
        {
            case OPTION_OBLOCK:
                option_Oblock = parseValue(optarg);
                break;
            case OPTION_OSELECT:
                option_Oselect = parseValue(optarg);
                break;
            case 'd': case OPTION_DEBUG:
                option_debug = true;
                break;
            case 'o':
                free(option_output);
                option_output = strdup(optarg);
                break;
            case OPTION_HELP:
                fprintf(stderr, "usage %s [OPTIONS] binary [e9tool-OPTIONS]\n",
                    argv[0]);
                fprintf(stderr,
                    "\n"
                    "OPTIONS:\n"
                    "\t-Oblock=never,default,always\n"
                    "\t\tApply bad block optimization.\n"
                    "\t-Oselect=never,default,always\n"
                    "\t\tApply selection optimization.\n"
                    "\t-d, --debug\n"
                    "\t\tEnable debugging output.\n"
                    "\t-o OUTPUT\n"
                    "\t\tSet OUTPUT to be the output binary filename.\n"
                    "\t-help\n"
                    "\t\tPrint this message\n\n");
                exit(0);
            default:
                error("failed to parse command-line options; try `--help' "
                    "for more information");
        }
    }

    // Get input/output files:
    if (optind >= argc)
        error("missing input file; try `--help' for more information");
    std::string input(argv[optind]);
    std::string output;
    if (option_output != nullptr)
        output += option_output;
    else
    {
        char *tmp = strdup(input.c_str());
        if (tmp == nullptr)
            error("failed to duplicate \"%s\" string: %s", input.c_str(),
                strerror(ENOMEM));
        output += basename(tmp);
        output += ".afl";
        free(tmp);
    }

    // Setup environment:
    std::string path;
    getExePath(path);
    setenv("E9AFL_OBLOCK",  getValue(option_Oblock), true);
    setenv("E9AFL_OSELECT", getValue(option_Oselect), true);
    setenv("E9AFL_DEBUG",   (option_debug? "always": "default"), true);
    setenv("E9AFL_PATH",    path.c_str(), true);

    // Construct command:
    std::string command;
    command += '\"';
    command += path;
    command += "/e9tool\" ";

    command += "--backend \"";
    command += path;
    command += "/e9patch\" ";

    command += "-o \"";
    command += output;
    command += "\" ";

    command += "-M 'plugin(\"";
    command += path;
    command += "/e9AFLPlugin.so\").match()' ";

    command += "-A 'plugin(\"";
    command += path;
    command += "/e9AFLPlugin.so\").patch()' ";

    for (int i = optind+1; i < argc; i++)
    {
        command += '\'';
        command += argv[i];
        command += "' ";
    }

    command += "-- \"";
    command += input;
    command += '\"';

    // Execute command:
    printf("%s\n", command.c_str());
    int result = system(command.c_str());
    if (result != 0)
        error("e9tool command failed with status (%d)", result);

    return 0;
}

