#define PROFILE  // turns on the reporting of timing results

#include "openfhe.h"
#include "utils.h"
#include "testcode.h"
#include "embedding.h"
#include "algorithms.h"


#include "schemerns/rns-leveledshe.h"

#include <iostream>
#include <getopt.h>

using namespace lbcrypto;
using namespace std;
using namespace ckkseif;

int main(int argc, char **argv) {

    int c;
    usint iteration = 8;
    bool indicator=false;
    bool anotherindicator=false;
    bool lutsynth=false;
    bool embedding=false;
    bool logregt=false;

    bool count=false;
    bool ngram=false;
    bool info=false;
    bool paralcount=false;

    bool any=true;

    while (1) {
        //int this_option_optind = optind ? optind : 1;
        int option_index = 0;
        static struct option long_options[] = {
            {"iteration",  required_argument, 0,  'i' },
            {"indicator", no_argument, 0,  's' },
            {"anotherindicator", no_argument, 0,  'a' },
            {"lutsynth", no_argument, 0,  'l' },
            {"embedding", no_argument, 0,  'e' },
            {"emball", no_argument,       0,  'x' },
            {"logreg", no_argument,       0,  'g' },

            {"count", no_argument,       0,  't' },
            {"ngram", no_argument,       0,  'm' },
            {"info", no_argument,       0,  'o' },
            {"countall", no_argument,       0,  'b' },
            {"paralcount", no_argument,       0,  'c' },


        };

        c = getopt_long(argc, argv, "abc:d:012v",
                long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 0:
            cout << "option" << long_options[option_index].name << endl;
            if (optarg)
                cout << " with arg: " << optarg << endl;
            break;

        case '0':
        case '1':
        case '2':
            // if (digit_optind != 0 && digit_optind != this_option_optind)
            //   printf("digits occur in two different argv-elements.\n");
            // digit_optind = this_option_optind;
            // printf("option %c\n", c);
            break;

        case 'i':
            iteration=(usint)*optarg-48;
            break;

        case 'a':
            anotherindicator=true;
            any=false;
            break;
        
        case 's':
            indicator=true;
            any=false;
            break;

	    case 'l':
            lutsynth=true;
            any=false;
			break;
        case 'e':
            embedding=true;
            any=false;
            break;

        case 'g':
            logregt=true;
            any=false;
            break;

        case 'x':
            indicator=true;
            anotherindicator=true;
            lutsynth=true;
            embedding=true;
            logregt=true;
            any=false;
            break;

        case 't':
            count=true;
            any=false;
            break;

        case 'm':
            ngram=true;
            any=false;
            break;

        case 'o':
            info=true;
            any=false;
            break;

        case 'c':
            paralcount=true;
            any=false;
            break;


        case 'b':
            count=true;
            ngram=true;
            paralcount=true;
            info=true;
            any=false;
            break;


        default:
            cout << "?? getopt returned character code 0" << c << endl;
        }
    }

    if (optind < argc) {
        cout << "non-option ARGV-elements: " << endl;
        while (optind < argc)
            cout << argv[optind++] << endl;
    }

    cout << "20241101 Version" << endl;

    if(any){
        indicator=true;
        anotherindicator=true;
        lutsynth=true;
        embedding=true;
        logregt=true;
        count=true;
        ngram=true;
        paralcount=true;
        info=true;
        any=false;
    }

    cout << "iteration set to " << iteration << endl;

    if(indicator){
        IndicatorTests(iteration, 35);
        IndicatorTests(iteration, 50);
    }

    if(lutsynth)LUTSynthTests(8, 2, 16, iteration);

    if(embedding)EmbeddingSIMDTests(iteration);

    if(anotherindicator)AnotherIndicatorTests(iteration);

    if(logregt){
        LogregTests(iteration);
    }

    if(count){
        usint base = 2;
        usint dim = 8;
        usint rotsize=256; //0 if fullslot

	    NaiveCountTest(50,pow(base,dim), rotsize, iteration);
	    CodedCountTest(50, base, dim, rotsize, 1, iteration); // sf, base, dim, size, exponentbound, iter 
        CodedCountTest(50, base, dim, rotsize, 4, iteration); // sf, base, dim, size, exponentbound, iter 
    }
    if(ngram){
        usint rotsize=256; //0 if fullslot

        NgramTest(50, 2, 4, rotsize, 4, 2, 0, iteration); //sf, base, dim, size, exponentbound, n, iter 
        NgramTest(50, 2, 4, rotsize, 4, 3, 0, iteration); //sf, base, dim, size, exponentbound, n, iter 
        NgramTest(50, 2, 6, rotsize, 6, 2, 10, iteration); //sf, base, dim, size, exponentbound, n, iter 
        NgramTest(50, 2, 6, rotsize, 6, 2, 50, iteration); //sf, base, dim, size, exponentbound, n, iter 
        NgramTest(50, 2, 6, rotsize, 6, 3, 0.1, iteration); //sf, base, dim, size, exponentbound, n, iter 
    }
    if(paralcount){
        usint scalingfactor = 50;
        CodedCountSIMDTest(scalingfactor, 2, 8, 256, 256, iteration);
        CodedCountSIMDTest(scalingfactor, 2, 8, 4096, 256, iteration);
        CodedCountSIMDTest(scalingfactor, 2, 8, 16384, 256, iteration);

    }
    if(info){
        usint scalingfactor = 50;
        CodedCountSIMDTest(scalingfactor, 2, 10, 256, 256, iteration);

        InfoRetrievalAfterTFTest(scalingfactor, 256, 1024, iteration);
        InfoRetrievalAfterTFTest(scalingfactor, 512, 1024, iteration);
        InfoRetrievalAfterTFTest(scalingfactor, 1024, 1024, iteration);
    }

    
    return 0;

}   