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

void HELUTExperiments(usint iteration){
    IndicatorTests(iteration, 35);
    IndicatorTests(iteration, 50);

    LUTSynthTests(8, 2, 16, iteration);
 	//EmbeddingTests(iteration);
 	EmbeddingSIMDTests(iteration);
    //EmbeddingTest(8,8,50,1); // 88526 
    //EmbeddingSIMDTest(8,8,50,1); //10201
    AnotherIndicatorTests(iteration);
}

void dezTests(usint iteration){
    dezTest(3, 8, iteration, 35); 
    dezTest(6, 8, iteration, 35); 
    dezTest(3, 8, iteration, 50); 
    dezTest(6, 8, iteration, 50); 

}



int main(int argc, char **argv) {

    int c;
    // int digit_optind = 0;
	// int flag = 0;
    usint iteration = 1;
    bool indicator=false;
    bool anotherindicator=false;
    bool lutsynth=false;
    bool embedding=false;
    bool dez=false;


    while (1) {
        //int this_option_optind = optind ? optind : 1;
        int option_index = 0;
        static struct option long_options[] = {
            {"iteration",  required_argument, 0,  'i' },
            {"indicator", no_argument, 0,  's' },
            {"anotherindicator", no_argument, 0,  'a' },
            {"lutsynth", no_argument, 0,  'l' },
            {"embedding", no_argument, 0,  'e' },
            {"dez", no_argument, 0,  'd' },
            {"all", no_argument,       0,  'x' },

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
            cout << "iteration set to " << iteration << endl;
            break;

        case 'a':
            anotherindicator=true;
            break;
        
        case 's':
            indicator=true;
            break;

	    case 'l':
            lutsynth=true;
			break;
        case 'e':
            embedding=true;
            break;

        case 'd':
            dez=true;
            break;

        case 'x':
            indicator=true;
            anotherindicator=true;
            lutsynth=true;
            embedding=true;
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

    if(indicator){
        IndicatorTests(iteration, 35);
        IndicatorTests(iteration, 50);
    }
    if(lutsynth)LUTSynthTests(8, 2, 16, iteration);
    if(embedding)EmbeddingSIMDTests(iteration);
    if(anotherindicator)AnotherIndicatorTests(iteration);
    if(dez)dezTests(iteration);


    return 0;

}   