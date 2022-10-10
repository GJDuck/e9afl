/*
 *        ___    _    _____ _     
 *   ___ / _ \  / \  |  ___| |    
 *  / _ \ (_) |/ _ \ | |_  | |    
 * |  __/\__, / ___ \|  _| | |___ 
 *  \___|  /_/_/   \_\_|   |_____|
 * 
 * Copyright (C) 2022 National University of Singapore
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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>

#define STRING(s)               STRING_2(s)
#define STRING_2(s)             #s

#define REDFAT                  "/usr/share/redfat/"

enum Option
{
    OPTION_COUNTER,
    OPTION_OBLOCK,
    OPTION_OSELECT,
    OPTION_DEBUG,
    OPTION_REDFAT,
    OPTION_OUTPUT,
    OPTION_HELP,
    OPTION_VERSION,
};

enum Value
{
    VALUE_NEVER,
    VALUE_DEFAULT,
    VALUE_ALWAYS
};

enum Counter
{
    COUNTER_CLASSIC,
    COUNTER_NEVER_ZERO,
    COUNTER_SATURATED
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
 * Parse a counter.
 */
static Counter parseCounter(const char *str)
{
    if (strcmp(str, "classic") == 0)
        return COUNTER_CLASSIC;
    else if (strcmp(str, "neverzero") == 0)
        return COUNTER_NEVER_ZERO;
    else if (strcmp(str, "saturated") == 0)
        return COUNTER_SATURATED;
    error("failed to parse counter \"%s\"; expected one of "
        "{classic, neverzero, saturated}", str);
}

/*
 * Value to string.
 */
static const char *getValue(Value value)
{
    switch (value)
    {
        default:
        case VALUE_NEVER:
            return "never";
        case VALUE_DEFAULT:
            return "default";
        case VALUE_ALWAYS:
            return "always";
    }
}

/*
 * Counter to string.
 */
static const char *getCounter(Counter counter)
{
    switch (counter)
    {
        default:
        case COUNTER_CLASSIC:
            return "classic";
        case COUNTER_NEVER_ZERO:
            return "neverzero";
        case COUNTER_SATURATED:
            return "saturated";
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
    Counter option_counter = COUNTER_CLASSIC;
    bool option_redfat = false, option_debug = false;
    option_is_tty = isatty(STDERR_FILENO);
    char *option_output = nullptr;
    static const struct option long_options[] =
    {
        {"counter", required_argument, nullptr, OPTION_COUNTER},
        {"Oblock",  required_argument, nullptr, OPTION_OBLOCK},
        {"Oselect", required_argument, nullptr, OPTION_OSELECT},
        {"redfat",  no_argument,       nullptr, OPTION_REDFAT},
        {"debug",   no_argument,       nullptr, OPTION_DEBUG},
        {"help",    no_argument,       nullptr, OPTION_HELP},
        {"version", no_argument,       nullptr, OPTION_VERSION},
        {nullptr,   no_argument,       nullptr, 0}
    };
    while (true)
    {
        int idx;
        int opt = getopt_long_only(argc, argv, "dho:v", long_options, &idx);
        if (opt < 0)
            break;
        switch (opt)
        {
            case OPTION_COUNTER:
                option_counter = parseCounter(optarg);
                break;
            case OPTION_OBLOCK:
                option_Oblock = parseValue(optarg);
                break;
            case OPTION_OSELECT:
                option_Oselect = parseValue(optarg);
                break;
            case OPTION_REDFAT:
                option_redfat = true;
                break;
            case 'd': case OPTION_DEBUG:
                option_debug = true;
                break;
            case 'o':
                free(option_output);
                option_output = strdup(optarg);
                break;
            case 'h': case OPTION_HELP:
                fprintf(stderr, "usage %s [OPTIONS] binary [e9tool-OPTIONS]\n",
                    argv[0]);
                printf(
                    "\n"
                    "OPTIONS:\n"
                    "\t--counter=classic,neverzero,saturated\n"
                    "\t\tApply hitcount overflow mitigation.\n"
                    "\t-Oblock=never,default,always\n"
                    "\t\tApply bad block optimization.\n"
                    "\t-Oselect=never,default,always\n"
                    "\t\tApply selection optimization.\n"
                    "\t--redfat\n"
                    "\t\tApply RedFat memory safety checking.\n"
                    "\t-d, --debug\n"
                    "\t\tEnable debugging output.\n"
                    "\t-o OUTPUT\n"
                    "\t\tSet OUTPUT to be the output binary filename.\n"
                    "\t-h, --help\n"
                    "\t\tPrint this message.\n"
                    "\t-v, -version\n"
                    "\t\tPrint version information.\n\n");
                exit(EXIT_SUCCESS);
            case 'v': case OPTION_VERSION:
                printf("E9AFL " STRING(VERSION) "\n");
                exit(EXIT_SUCCESS);
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
    std::string plugin;
    plugin += '\"';
    plugin += path;
    plugin += "/e9AFLPlugin.so\"";
    std::string plugin_opt;
    plugin_opt += "--plugin=";
    plugin_opt += plugin;
    plugin_opt += ':';

    // Construct command:
    std::string command;
    command += '\"';
    command += path;
    command += "/e9tool\" ";

    command += "-E '\".plt\"' ";
    command += "-E '\".plt.got\"' ";
    command += "-O2 ";
    command += "--option --mem-granularity=4096 ";

    command += "-o \"";
    command += output;
    command += "\" ";

    command += "-M 'plugin(";
    command += plugin;
    command += ").match()' ";

    command += "-P 'plugin(";
    command += plugin;
    command += ").patch()' ";

    command += plugin_opt;
    command += "--counter=";
    command += getCounter(option_counter);
    command += ' ';

    command += plugin_opt;
    command += "-Oblock=";
    command += getValue(option_Oblock);
    command += ' ';

    command += plugin_opt;
    command += "-Oselect=";
    command += getValue(option_Oselect);
    command += ' ';

    if (option_debug)
    {
        command += plugin_opt;
        command += "--debug ";
    }

    if (option_redfat)
    {
        struct stat buf;
        errno = 0;
        if (stat(REDFAT "RedFatPlugin.so", &buf) != 0 ||
                (buf.st_mode & S_IXUSR) == 0)
        {
            if (errno == ENOENT)
                error("RedFat is not installed; the RedFat binaries can be "
                    "downloaded here: https://github.com/GJDuck/RedFat");
            else
                error("failed to verify the RedFat installation");
        }

        std::string plugin("\"" REDFAT "RedFatPlugin.so\"");
        std::string plugin_opt;

        plugin_opt += "--plugin=";
        plugin_opt += plugin;
        plugin_opt += ':';

        command += "-M 'plugin(";
        command += plugin;
        command += ").match()' ";

        command += "-P 'plugin(";
        command += plugin;
        command += ").patch()' ";

        command += plugin_opt;
        command += "-Xlowfat=false ";   // lowfat may cause false detections

        command += plugin_opt;
        command += "-Xreads=true ";

        command += plugin_opt;
        command += "-path=\"";
        command += REDFAT;
        command += "\" ";
    }

    command += plugin_opt; 
    command += "--path='";
    command += path;
    command += "' ";
 
    for (int i = optind+1; i < argc; i++)
    {
        command += '\'';
        command += argv[i];
        command += "' ";
    }

    if (!option_debug)
        command += "--option --log=false ";

    command += "-- \"";
    command += input;
    command += '\"';

    // Execute command:
    printf("%s\n", command.c_str());
    int result = system(command.c_str());
    if (result != 0)
        error("e9tool command failed with status (%d)", result);

    // Print example fuzz command:
    printf("Generated: %s%s%s\n\n",
        (option_is_tty? "\33[32m": ""), output.c_str(),
        (option_is_tty? "\33[0m": ""));
    printf("%sUSAGE%s:\n\n",
        (option_is_tty? "\33[33m": ""), (option_is_tty? "\33[0m": ""));
    printf("\tThe %s%s%s binary includes %s instrumentation.\n",
        (option_is_tty? "\33[33m": ""), output.c_str(),
        (option_is_tty? "\33[0m": ""),
        (option_redfat? "both AFL and RedFat": "AFL"));
    printf("\tTo use, run the following basic command template:\n\n");
    printf("\t    %s$ %safl-fuzz -m none -i in/ -o out/ -- %s [ ... ] %s\n\n",
        (option_is_tty? "\33[36m": ""),
        (option_redfat?
            "AFL_PRELOAD=/usr/share/redfat/libredfat.so \\\n\t        ": ""),
        output.c_str(), (option_is_tty? "\33[0m": ""));
    printf("\tSee the AFL%s documentation for more information.\n\n",
        (option_redfat? " and RedFat": ""));

    return 0;
}

