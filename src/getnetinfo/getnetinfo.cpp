#include<iostream>
#include<utility>
#include<tuple>
#include<map>
#include<string>
#include<memory>
#include<vector>
#include<exception>
#include<stdexcept>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct DataFieldBase {
    virtual ~DataFieldBase() {}
    virtual std::string to_string() =0;
};

struct VoidDataField : public DataFieldBase {
    virtual std::string to_string() {
        return std::string ( "<NULL>" );
    }
};

struct StringDataField : public DataFieldBase {
    std::string str;
    virtual std::string to_string() override {
        return str;
    }
};

struct IntegerDataField : public DataFieldBase {
    long long value;
    virtual std::string to_string() override {
        return std::to_string ( value );
    }
};

struct PrefixDataField : public DataFieldBase {
    int af=0;
    int mask=0;
    union {
        in_addr inet;
        in6_addr inet6;
    } addr;
    virtual std::string to_string() override {
        char addr[INET6_ADDRSTRLEN];
        if ( inet_ntop ( af,&addr,addr,INET6_ADDRSTRLEN ) == NULL ) {
            return std::string ( "[NOT A VALID PREFIX]" );
        }
        return std::string ( addr )+"/"+std::to_string ( mask );
    }
};

struct FilterDataField : public DataFieldBase {
    std::string target;
    std::string verb;
    std::string value;
    virtual std::string to_string() override {
        return target+' '+verb+' '+value;
    }
};

class DataTypeBase {
public:
    virtual const std::string& id() =0;
    virtual std::shared_ptr<DataFieldBase> parse ( const std::string& str ) =0;
    virtual ~DataTypeBase() {}
};

class StringDataType : public  DataTypeBase {
public:
    static const std::string id_string;
    virtual const std::string& id() override {
        return id_string;
    }
    virtual std::shared_ptr<DataFieldBase> parse ( const std::string& str ) override {
        auto ptr = std::make_shared<StringDataField>();
        ptr->str=str;
        return ptr;
    }
};

class IntegerDataType : public DataTypeBase {
public:
    static const std::string id_string;
    virtual const std::string& id() override {
        return id_string;
    }
    virtual std::shared_ptr<DataFieldBase> parse ( const std::string& str ) override {
        auto ptr = std::make_shared<IntegerDataField>();
        ptr->value = std::stoll ( str,nullptr,10 );
        return ptr;
    }
};

class PrefixDataType : public DataTypeBase {
public:
    static const std::string id_string;
    virtual const std::string& id() override {
        return id_string;
    }
    virtual std::shared_ptr<DataFieldBase> parse ( const std::string& str ) override {
        auto ptr = std::make_shared<PrefixDataField>();
        size_t slash_pos=str.rfind ( '/' );
        if ( slash_pos==std::string::npos ) {
            ptr->mask=-1;
        }
        std::string prefix_addr = str.substr ( 0,slash_pos );
        if ( inet_pton ( AF_INET, prefix_addr.c_str(), &ptr->addr.inet ) == 1 ) {
            ptr->af=AF_INET;
        } else if ( inet_pton ( AF_INET6, prefix_addr.c_str(), &ptr->addr.inet6 ) == 1 ) {
            ptr->af=AF_INET6;
        } else {
            throw std::invalid_argument ( "Invalid Prefix" );
        }
        if ( ptr->mask==-1 ) {
            if ( ptr->af==AF_INET ) ptr->mask=32;
            else if ( ptr->af==AF_INET6 ) ptr->mask=128;
        } else {
            std::string mask_str=str.substr ( slash_pos+1 );
            ptr->mask=std::stoi ( mask_str,nullptr,10 );
            if ( ( ptr->mask>32&&ptr->af==AF_INET ) || ( ptr->mask>128&&ptr->af==AF_INET6 ) ) throw std::invalid_argument ( "Invalid Prefix" );
        }
        return ptr;
    }
};

class FilterDataType : public DataTypeBase {
public:
    static const std::string id_string;
    virtual const std::string& id() override {
        return id_string;
    }
    virtual std::shared_ptr<DataFieldBase> parse ( const std::string& str ) override {
        auto ptr = std::make_shared<FilterDataField>();
        size_t verb_fpos=str.find_first_of ( "!=" );
        size_t verb_bpos=str.find_last_of ( "!=" );
        if ( verb_fpos==std::string::npos ) {
            throw std::invalid_argument ( "Invalid Prefix" );
        }
        ptr->target=str.substr ( 0,verb_fpos );
        ptr->verb=str.substr ( verb_fpos,verb_bpos-verb_fpos+1 );
        ptr->value=str.substr ( verb_bpos+1 );
        return ptr;
    }
};

const std::string StringDataType::id_string = "string";
const std::string IntegerDataType::id_string = "int";
const std::string PrefixDataType::id_string = "prefix";
const std::string FilterDataType::id_string = "filter";

class CommandParser {
public:
    typedef std::map<std::string,std::shared_ptr<DataTypeBase>> DataTypeList;
    typedef std::map<std::string,std::string> OptionList;
    typedef std::multimap<std::string,std::shared_ptr<DataFieldBase>> OptionVector;
private:
    DataTypeList type_list;
    OptionList option_list;
    OptionVector options;

public:
    void register_data_type ( std::shared_ptr<DataTypeBase> ptr ) {
        type_list.insert ( std::make_pair ( ptr->id(),ptr ) );
    }

    void register_option ( const std::string& name,const std::string datatype ) {
        option_list.insert ( std::make_pair ( name,datatype ) );
    }

    void do_parse ( int argc,char** argv ) {
        if ( argc==1 ) return;
        for ( int i=1; i<argc; ++i ) {
            std::string arg ( argv[i] );
            if ( arg[0]!='+' ) {
                auto ptr = std::make_shared<StringDataField>();
                ptr->str=arg;
                options.insert ( std::make_pair ( std::string ( "_extra" ),ptr ) );
                continue;
            }
            if ( arg.size() ==1 ) throw std::invalid_argument ( "Incomplete Option" );
            size_t sep_pos=arg.find ( ":" );
            if ( sep_pos==std::string::npos ) {
                options.insert ( std::make_pair ( arg.substr ( 1 ),std::shared_ptr<DataFieldBase> ( dynamic_cast<DataFieldBase*> ( new VoidDataField ) ) ) );
                continue;
            } else {
                std::string option_name=arg.substr ( 1,sep_pos-1 );
                std::string option_value=arg.substr ( sep_pos+1 );
                if ( option_list.find ( option_name ) ==option_list.end() ) throw std::invalid_argument ( "Unknown Option" );
                options.insert ( std::make_pair (
                                     option_name,
                                     type_list[option_list[option_name]]->parse ( option_value )
                                 ) );
            }
        }
    }

    const OptionVector& get_options() {
        return options;
    }

};

int main ( int argc, char** argv ) {
    CommandParser cmd_parser;
    cmd_parser.register_data_type ( std::make_shared<StringDataType>() );
    cmd_parser.register_data_type ( std::make_shared<IntegerDataType>() );
    cmd_parser.register_data_type ( std::make_shared<PrefixDataType>() );
    cmd_parser.register_data_type ( std::make_shared<FilterDataType>() );
    cmd_parser.register_option ( "trunc","int" );
    cmd_parser.register_option ( "filter","filter" );
    cmd_parser.register_option ( "type","string" );
    cmd_parser.do_parse ( argc,argv );
    const CommandParser::OptionVector& options = cmd_parser.get_options();
    for ( const auto& item : options ) {
        std::cout<<item.first<<" == "<<item.second->to_string() <<std::endl;
    }
    return 0;
}
