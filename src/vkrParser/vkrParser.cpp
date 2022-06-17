#include "vkrParser.h"
using namespace std;


struct ST_KEY_SET
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

    void PrintData()
    {
        printf("%s  ", date.c_str());
        printf("%s  ", ext.c_str());
        printf("%s  ", detection.c_str());
        printf("%s  ", detection_name.c_str());
        printf("%s  ", engine_ver.c_str());
        printf("%s  ", elapsed_time.c_str());
        printf("%s  ", file_path.c_str());
        printf("%s  ", sha256.c_str());
        printf("%s  ", vt_positives.c_str());
        printf("%s  ", vt_total.c_str());
        printf("%s  ", vt_keyword.c_str());
    }
};

/*  vkr Paser Global variables  */
std::vector<ST_KEY_SET> vecKeySet;
vector<vector<string>> vecKey;

ifstream readFile;



ST_KEY_SET vkrPaser(string ValTempStr)
{
    istringstream iss(ValTempStr);
    string stringBuf;
	std::vector<string> vecVal;

    for (size_t j = 0; j< sizeof(ST_KEY_SET); j++)
    {
        getline(iss, stringBuf, ',');
        vecVal.push_back(stringBuf);
    }

    ST_KEY_SET stKeySet;
    stKeySet.date = vecVal[0];
    stKeySet.ext = vecVal[1];
    stKeySet.detection = vecVal[2];
    stKeySet.detection_name = vecVal[3];
    stKeySet.engine_ver = vecVal[4];
    stKeySet.elapsed_time = vecVal[5];
    stKeySet.file_path = vecVal[6];
    stKeySet.sha256 = vecVal[7];
    stKeySet.vt_positives = vecVal[8];
    stKeySet.vt_total = vecVal[9];
    stKeySet.vt_keyword = vecVal[10];

    return stKeySet;
}


void DataSort(const char* fName)
{
    readFile.open(fName);

    if (readFile.is_open())
    {
        if (readFile.good())
        {
            /* 첫 줄 읽어와서 백업해두기 */
            string tmpKey;
            getline(readFile, tmpKey);
            size_t nPos = tmpKey.find("elapsed_time");
            
            if (nPos != string::npos)
            {
                // runtime error 방지
            }
           
            while (!readFile.eof())
            {
                string valTemp;

                getline(readFile, valTemp);
                
                vecKeySet.push_back(vkrPaser(valTemp));
            }
            readFile.close();
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

std::vector<std::string> GetAllHashByDetection(std::vector<ST_KEY_SET> vecKeySet, std::string DetectionName)
{
    /* Get All sha256 from vkr file with target is benigned*/
    std::vector<std::string> vecHash;

    for (auto iter : vecKeySet)
    {
        if (!strcmp(iter.detection.c_str(), DetectionName.c_str()))
        {   vecHash.push_back(iter.sha256);     }
    }
    return vecHash;
}

std::vector<std::string> GetAllBenignHashByExt(std::vector<ST_KEY_SET> vecKeySet, std::string ExtentionName, std::string DetectionName)
{
    /* Get Hash By Extention With beniged sample list */

    std::vector<std::string> vecHash;

    for (auto iter : vecKeySet)
    {
        if (!strcmp(iter.ext.c_str(), ExtentionName.c_str()))
        {
            if (!strcmp(iter.detection.c_str(), DetectionName.c_str()))
                vecHash.push_back(iter.sha256);
        }
    }
    return vecHash;
}



int main(int argc, char* argv[])
{
    const char* fName = "./20220614.vkr";
    DataSort(fName);

    /* ST_KEY_SET에 저장된 모든 값을 출력
    for (auto iter : vecKeySet)
    {   iter.PrintData();   printf("\n");   }
    */


    /* 원하는 extention 값을 가진 대상 중에 Detection 값이 Benign 인 모든 sha256 해시 가져오기 */
    std::vector<std::string> vecToDownHash = GetAllBenignHashByExt(vecKeySet, "EXE", "Benign");
    printf("GetAllBenignHashByExt() Test\n\n");
    for (auto j : vecToDownHash)
    {   printf("%s\n", j.c_str()); }


    /* Detection 값이 Benign 인 모든 sha256 해시 가져오기 */
    std::vector<std::string> vecBenignHash = GetAllHashByDetection(vecKeySet, "Benign");
    printf("GetAllHAshByDetection() Test\n\n");
    for (auto i : vecBenignHash)
    {   printf("%s\n", i.c_str());  }

    system("pause");
    return 0;
}