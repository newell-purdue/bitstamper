//Author: Andrew Newell
//Description: BitStamper utility

#include<sys/types.h>
#include<dirent.h>
#include<iostream>
#include<list>
#include<algorithm>
#include<limits>
#include<sys/stat.h>
#include<unistd.h>
#include<math.h>
#include<vector>
#include<openssl/sha.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<time.h>
#include<bignum.h>
//#include<base58.h>
#include<termios.h>

#define BUFFER_SIZE 4096

using namespace std;
bool verbose=false;

static const char* pszBase58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

void SetStdinEcho(bool enable);

string EncodeBase58(const unsigned char* pbegin, const unsigned char* pend) {
    CAutoBN_CTX pctx;
    CBigNum bn58 = 58;
    CBigNum bn0 = 0;
    
    // Convert big endian data to little endian
    // Extra zero at the end make sure bignum will interpret as a positive number
    vector<unsigned char> vchTmp(pend-pbegin+1, 0);
    reverse_copy(pbegin, pend, vchTmp.begin());
    
    // Convert little endian data to bignum
    CBigNum bn;
    bn.setvch(vchTmp);
    
    // Convert bignum to std::string
    std::string str;
    // Expected size increase from base58 conversion is approximately 137%
    // use 138% to be safe
    str.reserve((pend - pbegin) * 138 / 100 + 1);
    CBigNum dv;
    CBigNum rem;
    while (bn > bn0)
    {
        if (!BN_div(&dv, &rem, &bn, &bn58, pctx))
        throw bignum_error("EncodeBase58 : BN_div failed");
        bn = dv;
        unsigned int c = rem.getulong();
        str += pszBase58[c];
    }
    
    // Leading zeroes encoded as base58 zeros
    for (const unsigned char* p = pbegin; p < pend && *p == 0; p++)
    str += pszBase58[0];
    
    // Convert little endian std::string to big endian
    reverse(str.begin(), str.end());
    return str;
}

void help() {
    cout << "usage:" << endl;
    cout << "  bitstamp [-h] [-b] [-j] [-v] [-a account-to-use] [-d dir-of-blocks] [-f stamp-fee] (validate|stamp) file" << endl;
    cout << "    -h      help" << endl;
    cout << "    -b      scan from beginning of block chain" << endl;
    cout << "    -j      just print address to send to for stamping" << endl;
    cout << "    -v      verbose mode" << endl;
    cout << "    -a arg  use account arg" << endl;
    cout << "    -d arg  use directory arg for block chain (default ~/.bitcoin)" << endl;
    cout << "    -f arg  use arg fee for sending" << endl;
}

void argumentError() {
    cout << "Incorrect arguments!" << endl;
    help();
    exit(1);
}

string hashToString(unsigned char* hash,int n) {
    char outputBuffer[2*n+1];
    for(int i=0;i<n;i++) {
        sprintf(outputBuffer+(i*2),"%02x",hash[i]);
    }
    outputBuffer[2*n]=0;
    return string(outputBuffer);
}

void realSha256(unsigned char* data,int size,unsigned char hash[SHA256_DIGEST_LENGTH]) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256,data,size);
    SHA256_Final(hash,&sha256);
}

void calcSha1(const char* path,unsigned char hash[SHA_DIGEST_LENGTH]) {
    FILE* file=fopen(path,"rb");
    if(file==NULL) {
        cout << "invalid path " << string(path) << endl;
        exit(1);
    }
    
    SHA_CTX sha;
    SHA1_Init(&sha);
    char buffer[BUFFER_SIZE];
    int bytesRead=0;
    while((bytesRead=fread(buffer,1,BUFFER_SIZE,file))!=0) {
        SHA1_Update(&sha,buffer,bytesRead);
    }
    SHA1_Final(hash,&sha);
    if(verbose) {
        cout << "Calculated SHA1 hash of " << string(path) << ":" << endl;
        cout << "  " << hashToString(hash,SHA_DIGEST_LENGTH) << endl;    
    }
    fclose(file);
}      

void calcSha256(char* path,unsigned char hash[SHA256_DIGEST_LENGTH]) {
    FILE* file=fopen(path,"rb");
    if(file==NULL) {
        cout << "invalid path " << string(path) << endl;
        exit(1);
    }
    
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    char buffer[BUFFER_SIZE];
    int bytesRead=0;
    while((bytesRead=fread(buffer,1,BUFFER_SIZE,file))!=0) {
        SHA256_Update(&sha256,buffer,bytesRead);
    }
    SHA256_Final(hash,&sha256);
    if(verbose) {
        cout << "Calculated SHA256 hash of " << string(path) << ":" << endl;
        cout << "  " << hashToString(hash,SHA256_DIGEST_LENGTH) << endl;    
    }
    fclose(file);
}      

class Matcher {
    private:
    list<int> indices;
    char* toMatch;
    int num;
    public:
    Matcher(char* x,int n) {
        num=n;
        toMatch=(char*)malloc(num);
        for(int i=0;i<n;i++) {
            toMatch[i]=x[i];
//            toMatch[n-1-i]=x[i];
        }
        //memcpy(toMatch,x,num);
    }
    bool check(char x) {
        //unsigned char t=x;
        //printf("%02x",t);
        bool found=false;
        list<list<int>::iterator> toRemove;
        for(list<int>::iterator i=indices.begin();i!=indices.end();i++) {
            (*i)++;
            if(x!=toMatch[(*i)]) {
                toRemove.push_back(i);
            } else if(*i==num-1) {
                found=true;
                toRemove.push_back(i);
            }
        }
        if(x==toMatch[0]) {
            indices.push_back(0);
        }
        for(list<list<int>::iterator>::iterator i=toRemove.begin();i!=toRemove.end();i++) {
            indices.erase(*i);
        }
        return found;
    }
};

class TimeKeeper {
    private:
    unsigned long int bytesCheckpoint;
    unsigned long int bytesRead;
    set<int> realTimes;
    int blockNum;
    time_t currentTime;
    int bytesToSize;
    int bytesToTime;
    unsigned int nextSize;
    unsigned int nextTime;
    bool timeSet;
    public:
    unsigned long int getBytesRead() {
        return bytesCheckpoint;
    }
    TimeKeeper() {
        timeSet=false;
        bytesToSize=8;
        nextTime=0;
        nextSize=0;
        blockNum=-1;
        bytesRead=0;
    }
    string getTime() {
        if(!timeSet) {
            return "";
        }
        return string(ctime(&currentTime));
    }
    void read(unsigned char x) {
        bytesRead++;
        bytesToSize--;
        bytesToTime--;
        if(bytesToSize<4) {
            nextSize+=pow(256,3-bytesToSize)*x;
            if(bytesToSize==0) {
                bytesToSize=nextSize+8;
                bytesToTime=72;
                nextSize=0;
                blockNum++;
                bytesCheckpoint=bytesRead-8;
                if(timeSet) {
                    if(verbose) {
                        int realTime=time(NULL);
                        if(realTimes.count(realTime)==0) {
                            realTimes.insert(realTime);
                            cout << "Checked up to " << getTime();
                            cout << bytesRead << " bytes read so far\n";
                        }
                    }
                }
            }
        }
        if(bytesToTime<4&&bytesToTime>=0) {
            nextTime+=pow(256,3-bytesToTime)*x;
            if(bytesToTime==0) {
                currentTime=nextTime;
                timeSet=true;
                nextTime=0;
            }
        }
        /*        cout << "bytes to next size " << bytesToSize << endl;
        cout << "bytes to next time " << bytesToTime << endl;
        cout << "current time " << getTime() << endl;*/
    }
};

string hashToAddress(unsigned char hash[SHA_DIGEST_LENGTH]) {
    unsigned char firstHash[SHA256_DIGEST_LENGTH];
    unsigned char secondHash[SHA256_DIGEST_LENGTH];
    unsigned char bitAddress[25];
    bitAddress[0]=0;
    memcpy(bitAddress+1,hash,20);
    realSha256(bitAddress,21,firstHash);
    realSha256(firstHash,SHA256_DIGEST_LENGTH,secondHash);
    memcpy(bitAddress+21,secondHash,4);
    return EncodeBase58(bitAddress,bitAddress+25);
}

void quickPseudoUnitTestMatcher() {
    char toSearch[]="aaabab";
    char searchin[]="aaaaaaaaaaaababaaaababaaaaaaaabbdfbdbaaaaaabab";
    Matcher xx(toSearch,5);
    for(int i=0;i<strlen(searchin);i++) {
        cout << searchin[i];
        if(xx.check(searchin[i])) {
            cout << "!";
        }
    }
    exit(0);    
}

list<string> getAllFiles(string x) {
    list<string> files;
    DIR* dir=opendir(x.c_str());
    if(dir==NULL) {
        files.push_back(x);
        return files;
    }
    struct dirent* dp;
    while((dp=readdir(dir))!=NULL) {
        if(string(dp->d_name)=="."||string(dp->d_name)=="..") {
            continue;
        }
        list<string> temp=getAllFiles(x+"/"+dp->d_name);
        for(list<string>::iterator i=temp.begin();i!=temp.end();i++) {
            files.push_back(*i);
        }
    }
    closedir(dir);
    return files;
}

set<string> getBlockFiles(string blockDir) {
    set<string> blockFiles;
    list<string> allFiles=getAllFiles(blockDir);
    for(list<string>::iterator i=allFiles.begin();i!=allFiles.end();i++) {
        int n=(*i).size();
        string firstPart=(*i).substr(n-13,4);
        string secondPart=(*i).substr(n-4,4);
        bool allNumbers=true;
        set<string> digits;
        digits.insert("0");
        digits.insert("1");
        digits.insert("2");
        digits.insert("3");
        digits.insert("4");
        digits.insert("5");
        digits.insert("6");
        digits.insert("7");
        digits.insert("8");
        digits.insert("9");
        for(int j=0;j<5;j++) {
            if(digits.count((*i).substr(n-5-j,1))==0) {
                allNumbers=false;
            }
        }
        if(allNumbers&&firstPart=="/blk"&&secondPart==".dat") {
            blockFiles.insert(*i);
            if(verbose) {
                cout << "File " << (*i) << " added to be checked, assumed to be part of block chain" << endl;
            }
        }
    }
    return blockFiles;
}

int main(int argc,char* argv[]) {
    bool justAddress=false;
	bool walletEncrypted=true;
    string blockDir="";
    string feeAmt="";
    string fileName="";
    string action="";
    string fromAccount="";
    bool beginningStart=false;
    for(int i=1;i<argc;i++) {
        if(strcmp(argv[i],"-d")==0) {
            i++;
            if(i==argc) {
                argumentError();
            }
            blockDir=string(argv[i]);
        } else if(strcmp(argv[i],"-b")==0) {
            if(beginningStart) {
                argumentError();
            }
            beginningStart=true;
        } else if(strcmp(argv[i],"-j")==0) {
            if(justAddress) {
                argumentError();
            }
            justAddress=true;
        } else if(strcmp(argv[i],"-h")==0) {
            cout << "The following describes how to use bitstamp" << endl;
            help();
            exit(0);
        } else if(strcmp(argv[i],"-v")==0) {
            if(verbose) {
                argumentError();
            }
            verbose=true;
        } else if(strcmp(argv[i],"-a")==0) {
            i++;
            if(i==argc) {
                argumentError();
            }
            fromAccount=string(argv[i]);
        } else if(strcmp(argv[i],"-f")==0) {
            i++;
            if(i==argc) {
                argumentError();
            }
            feeAmt=string(argv[i]);
        } else if(action=="") {
            action=string(argv[i]);
            if(action!="validate"&&action!="stamp") {
                argumentError();
            }
        } else if(fileName=="") {
            fileName=string(argv[i]);
        } else {
            argumentError();
        }
    }
    if(fileName==""||action=="") {
        argumentError();
    }
    unsigned long int bytesToSkip;
    if(beginningStart) {
        bytesToSkip=0;
    } else {
        //bytesToSkip=7142202419;
//        bytesToSkip=99243107-8+157388147-8+6839349118-8;
bytesToSkip=7135458961;
    }
    unsigned char hash[SHA_DIGEST_LENGTH];
    calcSha1(fileName.c_str(),hash);
    if(action=="validate") {
        Matcher m((char*)hash,SHA_DIGEST_LENGTH);
        TimeKeeper t;
        if(blockDir=="") {
            char* homeDir=getenv("HOME");
            if(homeDir==NULL) {
                cout << "error no HOME environment variable" << endl;
            }
            blockDir=string(homeDir)+"/.bitcoin";
        }
        set<string> blockFiles=getBlockFiles(blockDir);
        unsigned long int unchangedSkipBytes=bytesToSkip;
        for(set<string>::iterator i=blockFiles.begin();i!=blockFiles.end();i++) {
            struct stat s;
            if(stat((*i).c_str(),&s)==-1) {
                cout << "Couldn't stat " << (*i) << endl;
                exit(1);
            }
            if(verbose) {
                cout << bytesToSkip << " " << s.st_size << endl;
            }
            if(((unsigned long int)s.st_size)<=bytesToSkip) {
                bytesToSkip-=s.st_size;
                if(verbose) {
                    cout << "skipping file " << (*i) << endl;
                }
                continue;
            }
            string blockName=(*i);
            FILE* file=fopen(blockName.c_str(),"rb");
            fseek(file,(long)bytesToSkip,SEEK_CUR);
            if(verbose) {
                cout << "opened file " << blockName << endl;
            }
            if(verbose&&bytesToSkip>0) {
                cout << "skipping " << bytesToSkip << " bytes" << endl;
            }
            bytesToSkip=0;
            if(file==NULL) {
                cout << "error openening block chain file " << blockName << endl;
                exit(1);
            }
            int c=fgetc(file);
            while(c!=EOF) {
                if(m.check(c)) {
                    cout << "Stamp found! \"" << fileName << "\" was timestamped at " << t.getTime();
                    if(verbose) {
                        cout << t.getBytesRead() << " bytes actually read" << endl;
                        cout << "total " << (unchangedSkipBytes+t.getBytesRead()) << " bytes read" << endl;
                    }
                    exit(0);
                }
                t.read(c);
                c=fgetc(file);
            }
            fclose(file);
        }
        cout << "Stamp for " << fileName << " never found" << endl;
        if(verbose) {
            cout << t.getBytesRead() << " bytes actually read" << endl;
            cout << "total " << (unchangedSkipBytes+t.getBytesRead()) << " bytes read" << endl;
        }
        exit(0);
    } else if(action=="stamp") {
        string base58Hash=hashToAddress(hash);
        if(justAddress) {
            cout << "Send a BTC payment of any amount to " << base58Hash << " to bitstamp the file " << fileName << endl;
            exit(0);
        }
        if(feeAmt!="") {
            string cmd="bitcoind settxfee "+feeAmt;
            if(verbose) {
                cout << cmd << endl;
            }
            if(system(cmd.c_str())==-1) {
                cout << "couldn't set transaction fee" << endl;
                exit(1);
            }
        }
	    if(walletEncrypted) {
			SetStdinEcho(false);
			string passphrase = "";
			cout << "Enter your wallet passphrase (will not echo): \n";
			getline(cin,passphrase);
			string cmd="bitcoind walletpassphrase \""+passphrase+"\" 10"; // 10 second timeout
			passphrase = ""; // paranoia?
			SetStdinEcho(true);
            if(verbose) {
                cout << "bitcoind walletpassphrase [your passphrase here] 10" << endl;
            }
            if(system(cmd.c_str())==-1) {
                cout << "couldn't decrypt wallet" << endl;
                exit(1);
            }
		}
        if(fromAccount!="") {
            string cmd="bitcoind sendtoaddress "+fromAccount+" "+base58Hash+" 0.00000001";
            if(verbose) {
                cout << cmd << endl;
            }
            if(system(cmd.c_str())==-1) {
                cout << "couldn't send bitcoins" << endl;
                exit(1);
            }
        } else {
            string cmd="bitcoind sendtoaddress "+base58Hash+" 0.00000001";
            if(verbose) {
                cout << cmd << endl;
            }
            if(system(cmd.c_str())==-1) {
                cout << "couldn't send bitcoins" << endl;
                exit(1);
            }
        }
	    if(walletEncrypted) {
			string cmd="bitcoind walletlock";
            if(verbose) {
                cout << cmd << endl;
            }
            if(system(cmd.c_str())==-1) {
                cout << "couldn't relock wallet" << endl;
                exit(1);
            }
		}
    } else {
        argumentError();
    }
}

void SetStdinEcho(bool enable = true)
{
// taken from http://stackoverflow.com/posts/1455007/revisions
#ifdef WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE); 
    DWORD mode;
    GetConsoleMode(hStdin, &mode);

    if( !enable )
        mode &= ~ENABLE_ECHO_INPUT;
    else
        mode |= ENABLE_ECHO_INPUT;

    SetConsoleMode(hStdin, mode );

#else
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if( !enable )
        tty.c_lflag &= ~ECHO;
    else
        tty.c_lflag |= ECHO;

    (void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}
