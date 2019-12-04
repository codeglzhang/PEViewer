package com.codegang.peviewer;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.List;

/**
 * 导出描述符
 * @author CodeGang
 * @since jdk1.8 2019/12/3
 */
public class ExportDescriptor {
    public long characteristics;
    public long timeDateStamp;
    public long majorVersion;
    public long minorVersion;
    public long nameRva;
    public long nameRaw;
    public long base;
    public long numberOfFunctions;
    public long numberOfNames;
    public long rvaOfFunctions;
    public long rvaOfNames;
    public long rvaOfNameOrdinals;

    public ExportDescriptor(){}

    /**
     * 根据截取的字节数组，填充进导出描述符
     * @param bytes 截取好的字节数组
     */
    public ExportDescriptor(final byte[] bytes){

        //调整字节序
        byte[] tmp = new byte[bytes.length];
        System.arraycopy(bytes,0,tmp,0,tmp.length);
        Utils.reverseByteArray(tmp);

        rvaOfNameOrdinals = Utils.longFromBytes(tmp,0,4);
        rvaOfNames = Utils.longFromBytes(tmp,4,4);
        rvaOfFunctions = Utils.longFromBytes(tmp,8,4);
        numberOfNames = Utils.longFromBytes(tmp,12,4);
        numberOfFunctions = Utils.longFromBytes(tmp,16,4);
        base = Utils.longFromBytes(tmp,20,4);
        nameRva = Utils.longFromBytes(tmp,24,4);
        nameRaw= Utils.rvaToRaw(nameRva,InitialParameters.SECTION_HEADERS);
        minorVersion = Utils.longFromBytes(tmp,28,2);
        majorVersion = Utils.longFromBytes(tmp,30,2);
        timeDateStamp = Utils.longFromBytes(tmp,32,4);
        characteristics = Utils.longFromBytes(tmp,36,4);
    }

    /**
     * 获得PE文件中的导出表内容
     * @param reader PE文件对应的操作类
     * @return PE文件中所有的导出函数
     * @throws IOException 读取数据和重定位文件指针时，可能抛出异常
     */
    public List<ExportItem> getExportTable(RandomAccessFile reader) throws IOException {
        List<ExportItem> itemList = new ArrayList<ExportItem>();
        long raw =Utils.rvaToRaw(rvaOfFunctions,InitialParameters.SECTION_HEADERS);
        reader.seek(raw);
        byte[] dwordTmp = new byte[Constant.DWORD_SIZE];

        //获取EAT中所有函数的地址和ordinal的值
        for(int i=0; i<numberOfFunctions;i++){
            ExportItem item = new ExportItem();
            item.addressEat=raw+Constant.DWORD_SIZE*i;
            item.value = Utils.loadValue(reader,dwordTmp);
            itemList.add(item);
            item.ordinal=i;
        }
        //获取所有有名函数的ordinal值
        int[] ordinals = new int[(int) numberOfNames];
        byte[] wordTmp =new byte[Constant.WORD_SIZE];
        raw=Utils.rvaToRaw(rvaOfNameOrdinals,InitialParameters.SECTION_HEADERS);
        reader.seek(raw);
        for (int i=0;i<numberOfNames;i++){
            ordinals[i]= (int) Utils.loadValue(reader,wordTmp);
        }

        //根据ordinal的值，将函数名称填充进对应的导出函数中
        raw = Utils.rvaToRaw(rvaOfNames,InitialParameters.SECTION_HEADERS);
        for (int i=0; i<numberOfNames;i++){
            reader.seek(raw+Constant.DWORD_SIZE*i);
            ExportItem item = itemList.get(ordinals[i]);
            long nameRva = Utils.loadValue(reader,dwordTmp);
            reader.seek(Utils.rvaToRaw(nameRva,InitialParameters.SECTION_HEADERS));
            item.name = Utils.getString(reader);
        }
        return itemList;
    }

}
