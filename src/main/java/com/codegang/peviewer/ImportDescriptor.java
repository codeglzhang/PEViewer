package com.codegang.peviewer;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.List;

/**
 * 导入表项的描述符
 * @author CodeGang
 * @since jdk1.8 2019/12/3
 */
public class ImportDescriptor {
    public long intRva;
    public long timeDateStamp;
    public long forwarderChain;
    public long nameRva;
    public long iatRva;
    public long intRaw;
    public long nameRaw;
    public long iatRaw;


    public ImportDescriptor() {
    }

    /**
     * 根据截取好的字节数组，填充进导入表项的描述符
     * @param bytes 截取好的字节数组
     */
    public ImportDescriptor(byte[] bytes) {
        byte[] tmp = new byte[4];
        System.arraycopy(bytes,0,tmp,0,4);
        Utils.reverseByteArray(tmp);
        intRva = Utils.longFromBytes(tmp,0);
        intRaw = Utils.rvaToRaw(intRva,InitialParameters.SECTION_HEADERS);

        System.arraycopy(bytes,4,tmp,0,4);
        Utils.reverseByteArray(tmp);
        timeDateStamp = Utils.longFromBytes(tmp,0);

        System.arraycopy(bytes,8,tmp,0,4);
        Utils.reverseByteArray(tmp);
        forwarderChain = Utils.longFromBytes(tmp,0);

        System.arraycopy(bytes,12,tmp,0,4);
        Utils.reverseByteArray(tmp);
        nameRva = Utils.longFromBytes(tmp,0);
        nameRaw = Utils.rvaToRaw(nameRva,InitialParameters.SECTION_HEADERS);

        System.arraycopy(bytes,16,tmp,0,4);
        Utils.reverseByteArray(tmp);
        iatRva = Utils.longFromBytes(tmp,0);
        iatRaw = Utils.rvaToRaw(iatRva,InitialParameters.SECTION_HEADERS);
    }

    /**
     * 获得该描述符对应的导入函数组
     * @param reader PE文件操作类
     * @return 导入函数组
     * @throws IOException 读取文件或者文件指针重定位时会抛出
     */
    public  List<ImportItem> getImportTable(RandomAccessFile reader) throws IOException {
        List<ImportItem> list = new ArrayList();
        byte[] tmp = new byte[Constant.DWORD_SIZE];
        reader.seek(iatRaw);
        reader.read(tmp);
        int order = 0;

        //填充导入函数在Iat中的位置和函数的地址(在没有装载进内存时，此地址是无效的)
        while (Utils.hasData(tmp)){
            Utils.reverseByteArray(tmp);
            ImportItem importItem = new ImportItem();
            importItem.value = Utils.longFromBytes(tmp,0);
            importItem.addressIat = iatRaw+order*4*8;
            list.add(importItem);
            reader.read(tmp);
            order++;
        }

        //填充导入函数的名称和导入函数的序号
        byte[] hint =new byte[Constant.WORD_SIZE];
        order = 0;
        for (ImportItem item : list){
            reader.seek(intRaw+order*Constant.DWORD_SIZE);
            reader.read(tmp);
            Utils.reverseByteArray(tmp);
            long raw = Utils.longFromBytes(tmp,0);
            reader.seek(Utils.rvaToRaw(raw,InitialParameters.SECTION_HEADERS));

            reader.read(hint);
            Utils.reverseByteArray(hint);
            item.hint = (int) Utils.longFromBytes(hint,0);
            item.name=Utils.getString(reader);
            order++;
        }
        return list;
    }


}