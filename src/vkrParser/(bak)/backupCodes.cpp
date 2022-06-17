#include "CSVParser.h"
using namespace std;

struct stKeySet
{
    string date;
    string ext;
    string detection;
    string detection_name;
    string engine_ver;
    string elapsed_time;
    string file_path;
    string sha256;
    string vt_positives;
    string vt_total;
    string vt_keyword;
};


vector<vector<string>> vecKey; // 

ifstream readFile;
const char* fName = "C:\\Users\\miho0\\Desktop\\Malware_Arrestium\\2. R&D 관련\\CSVParse\\Build\\Debugx64\\20220614.vkr";



vector<string> DataSpliter(string OriginStr)
{
    istringstream iss(OriginStr);
    string stringBuf;

    vector<string> tmpVec;

    tmpVec.clear();
    while (getline(iss, stringBuf, ','))
    {   tmpVec.push_back(stringBuf);    }

    for (auto i : tmpVec) { printf("%s\n", i.c_str()); }

    return tmpVec;
}


void oneLineReader()
{
    readFile.open(fName);

    if (readFile.is_open())
    {
        if (readFile.good())
        {
            string tmpKey;
            getline(readFile, tmpKey);

            cout << "       Get 1 line from *.vkr extenstion" << endl;
            cout << tmpKey << endl;
            printf("    ---------------- result end ----------------\n\n");

            vector<string> vecKey = DataSpliter(tmpKey);
        }

        readFile.close();
    }
    else if (readFile.fail())
    {
        printf("[ERROR] File Open failure. \n");
        return;
    }
    else
    {
        printf("[ERROR] Unkown Error occured! \n");
    }
}

void MultiLineReader()
{
    readFile.open(fName);

    if (readFile.is_open())
    {
        if (readFile.good())
        {
            while (!readFile.eof())
            {
                string str;
                getline(readFile, str);
                cout << str << endl;
            }
            printf("[INFO] Succesfully load all data from %s\n\n", fName);
            readFile.close();
        }
        else if (readFile.fail())
        {
            printf("[ERROR] File open failure. \n");
            return;
        }
    }
}


std::vector<string> ValSpliter(string ValTempStr)
{
    istringstream iss(ValTempStr);
    string stringBuf;
	std::vector<string> vecVal;

    for (int j = 0; j< 11; j++)
    {
        getline(iss, stringBuf, ',');
        vecVal.push_back(stringBuf);
    }

    return vecVal;
}


void DataSort()
{
    readFile.open(fName);

    if (readFile.is_open())
    {
        if (readFile.good())
        {
            /* 첫 줄 읽어와서 키값으로 쓰기 */
            string tmpKey;
            getline(readFile, tmpKey);
            size_t nPos = tmpKey.find("elapsed_time");

            
            if (nPos != string::npos)
            {
                cout << "       Get 1 line and insert to vecKey " << endl;
                cout << tmpKey << endl;
                printf("    ---------------- result end ----------------\n\n");

                // 키가 모여있는 벡터
                vecKey.push_back(DataSpliter(tmpKey));
            }
           
            int loopCount = 0;
            while (!readFile.eof())
            {
                string valTemp;

                getline(readFile, valTemp);
                loopCount++;
                
                std::vector<string> vecVal = ValSpliter(valTemp);
                vecKey.push_back(vecVal);
            }
            readFile.close();
            printf("#=====================================================#\n\n");
            printf("Total Value Count : %d\n", loopCount);
            //MultiVecPrint(loopCount);
            printf("#=====================================================#\n\n");
        }
        else if (readFile.fail())
        {   printf("[ERROR] File Open failure. \n");    }
        else
        {   printf("[ERROR] Unkown Error occured.\n");  }
    }
    else
    {
        printf("[ERROR] file not found. ErroCode: %d\n", GetLastError());
    }
}

int main(int argc, char* argv[])
{
    //oneLineReader();
    //MultiLineReader();
    DataSort();


    //for (auto i : tmpVec) { printf("%s\n", i.c_str()); }
    //cout << "vecKey[en_date][3] : " << vecKey[en_date][3] << "\n";
    //cout << "vecKey[en_detection][1] : " << vecKey[en_detection][1] << "\n";

    for (auto iter : vecKey)
    {
        for (auto iter2 : iter)
        {
            printf("%s \t", (iter2).c_str());
        }
        printf("\n");
    }
    system("pause");
    return 0;
}