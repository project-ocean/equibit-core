// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "json.h"
#include <cctype>
#include <cassert>
#include <cstring>

namespace
{

const char * eatSpace(const char * cp, const char * end)
{
    while (cp != end && isspace(*cp))
        ++cp;
    return cp;
}

JSONnode * parse(const char * & cp, const char * end);

JSONnode * parseArray(const char * & cp, const char * end)
{
    assert(*cp == '[');
    std::unique_ptr<JSONarray> arr(new JSONarray());

    ++cp;
    // ws* value ws* [,|]]
    while (*cp != ']')
    {
        cp = eatSpace(cp, end);

        JSONnode * value = parse(cp, end);
        arr->add(value);

        cp = eatSpace(cp, end);

        if (*cp == ',')
        {
            ++cp; // no-op
        }
        else if (*cp == ']')
        {
            ++cp;
            break;
        }
        else
        {
            throw std::runtime_error("Invalid JSON:Elements of object not separated by comma");
        }

    }

    return arr.release();
}

JSONnode * parseObject(const char * & cp, const char * end)
{
    assert(*cp == '{');

    std::unique_ptr<JSONobject> obj(new JSONobject());

    ++cp;
    // ws* "name" ws* : ws* value ws* [,|}]
    while (*cp != '}')
    {
        cp = eatSpace(cp, end);

        // "name"
        if (*cp != '"')
            throw std::runtime_error("Invalid JSON:Elements of object not separated by comma");
        const char * n = ++cp;
        while (isalpha(*cp))
            ++cp;
        if (*cp != '"')
            throw std::runtime_error("Invalid JSON:Elements of object not separated by comma");
        std::string name(n, cp - n);
        ++cp;

        cp = eatSpace(cp, end);
        if (*cp != ':')
            throw std::runtime_error("Invalid JSON:Name/value pair is not separated by colon");
        ++cp;
        cp = eatSpace(cp, end);

        JSONnode * value = parse(cp, end);
        cp = eatSpace(cp, end);

        obj->add(name, value);

        if (*cp == ',')
        {
            ++cp; // move past it
        }
        else if (*cp == '}')
        {
            ++cp; // move past it
            break;
        }
        else
        {
            throw std::runtime_error("Invalid JSON:Elements of object not separated by comma");
        }
    }

    return obj.release();
}

JSONnode * parseString(const char * & cp, const char * end)
{
    assert(*cp == '"');

    const char * start = ++cp;

    while (cp != end && *cp != '"')
        ++cp;

    if (*cp != '"')
        throw std::runtime_error("Invalid JSON:Non-terminating string");

    return new JSONstring(start, cp++);
}

JSONnode * parseNumber(const char * & cp, const char * end)
{
    bool isNeg;

    if (*cp == '-')
    {
        isNeg = true;
        ++cp;
    }
    else
        isNeg = false;

    const char * start = cp;


    bool isInt = true;
    while ((cp < end) &&
        (*cp == '-' || isdigit(*cp) || *cp == 'e' || *cp == 'E' || *cp == '.' || *cp == '+'))
    {
        if (*cp == 'E' || *cp == 'e' || *cp == '.')
            isInt = false;
        ++cp;
    }

    if (isInt)
    {
        int64_t i64 = 0;
        while (start < cp)
        {
            i64 = i64 * 10 + *start - '0';
            ++start;
        }
        return new JSONint(isNeg ? -i64 : i64);
    }
    else
    {
        double d = atof(start);
        return new JSONdouble(isNeg ? -d : d);
    }
}

JSONnode * parseBool(const char * & cp, const char * end)
{
    if (strncmp(cp, "true", 4) == 0)
    {
        cp += 4;
        return new JSONbool(true);
    }
    else if (strncmp(cp, "false", 5) == 0)
    {
        cp += 5;
        return new JSONbool(false);
    }

    throw std::runtime_error("Invalid JSON:Invalid null value");
}

JSONnode * parseNull(const char * & cp, const char * end)
{
    if (strncmp(cp, "null", 4) == 0)
    {
        cp += 4;
        return new JSONnull();
    }
    throw std::runtime_error("Invalid JSON:Invalid null value");
}

JSONnode * parse(const char * & cp, const char * end)
{
    cp = eatSpace(cp, end);

    if (cp != end)
    {
        if (*cp == '[')
        {
            return parseArray(cp, end);
        }
        else if (*cp == '{')
        {
            return parseObject(cp, end);
        }
        else if (*cp == '"')
        {
            return parseString(cp, end);
        }
        else if (isdigit(*cp) || *cp == '-')
        {
            return parseNumber(cp, end);
        }
        else if (*cp == 'n')
        {
            return parseNull(cp, end);
        }
        else if (*cp == 't' || *cp == 'f')
        {
            return parseBool(cp, end);
        }

        throw std::runtime_error("Invalid JSON:Invalid value prefix");
    }
    else
        throw std::runtime_error("Invalid JSON:Missing value");
}

};


JSONnode * JSONnode::parse(const std::string & data)
{
    const char * cp = data.data();
    const char * end = cp + data.size();

    JSONnode * ans = ::parse(cp, end);

    cp = eatSpace(cp, end);

    if (cp != end)
    {
        delete ans;
        throw std::runtime_error("Invalid JSON:Invalid top level value");
    }

    return ans;
}

JSONnode * JSONnode::parse(const std::vector<unsigned char> & data)
{
    const char * cp = reinterpret_cast<const char *>(data.data());
    const char * end = reinterpret_cast<const char *>(cp + data.size());

    JSONnode * ans = ::parse(cp, end);

    cp = eatSpace(cp, end);

    if (cp != end)
    {
        delete ans;
        throw std::runtime_error("Invalid JSON:Invalid top level value");
    }

    return ans;
}

bool JSONobject::add(const std::string & s, JSONnode * jn)
{
    auto rc = value_.insert(std::make_pair(s, std::unique_ptr<JSONnode>(jn)));
    return rc.second;
}
