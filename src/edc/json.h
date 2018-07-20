// Copyright (c) 2016 Equibit Development Corporation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>


class JSONnode
{
public:

    enum Type
    {
        JOBJECT,  // { ... }
        JARRAY,   // [ ... ]
        JINT,     // 123
        JDOUBLE,  // 123.456
        JSTRING,  // "..."
        JBOOL,    // true or false
        JNULL     // null
    };

    virtual ~JSONnode() {}

    virtual Type type() const = 0;

    static JSONnode	* parse(const std::string &);
    static JSONnode	* parse(const std::vector<unsigned char> &);
};

class JSONobject : public JSONnode
{
public:
    Type type() const final { return JOBJECT; }

    bool add(const std::string & s, JSONnode * jn);

    const std::map<std::string, std::unique_ptr<JSONnode>> & value() const
    {
        return value_;
    }

private:

    std::map<std::string, std::unique_ptr<JSONnode>> value_;
};


class JSONarray : public JSONnode
{
public:
    Type type() const final { return JARRAY; }

    void add(JSONnode * jn)
    {
        value_.push_back(std::unique_ptr<JSONnode>(jn));
    }

    const std::vector<std::unique_ptr<JSONnode>> & value() const
    {
        return value_;
    }

private:
    std::vector<std::unique_ptr<JSONnode>>	value_;
};

class JSONdouble : public JSONnode
{
public:
    JSONdouble(double d) :value_(d) {}

    Type type() const final { return JDOUBLE; }

    double value() const { return value_; }

private:
    double value_;
};

class JSONint : public JSONnode
{
public:
    JSONint(int64_t i) :value_(i) {}

    Type type() const final { return JINT; }

    int64_t value() const { return value_; }

private:
    int64_t value_;
};


class JSONstring : public JSONnode
{
public:
    JSONstring(const char * cp, const char * end) :value_(cp, end - cp) {}

    Type type() const final { return JSTRING; }

    const std::string & value() const { return value_; }

private:
    std::string value_;
};


class JSONbool : public JSONnode
{
public:
    JSONbool(bool b) :value_(b) {}

    Type type() const final { return JBOOL; }

    bool value() const { return value_; }

private:
    bool value_;
};


class JSONnull : public JSONnode
{
public:

    Type type() const final { return JNULL; }

};
