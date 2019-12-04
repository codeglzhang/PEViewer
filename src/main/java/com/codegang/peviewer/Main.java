package com.codegang.peviewer;

import java.io.*;
import java.util.*;

/**
 * 程序入口
 * @author CodeGang
 * @since jdk 1.8 2019/12/3
 */
public class Main {
    /**装载类型为word的字节数据*/
    private static byte[] word = new byte[Constant.WORD_SIZE];
    /**装载类型为dword的字节数据*/
    private static byte[] dword = new byte[Constant.DWORD_SIZE];
    /**装载8字节的数据*/
    private static byte[] longWord = new byte[8];
    /***装载类型为BYTE的数据*/
    private static byte[] byteWord = new byte[1];
    /**用于记录数据在文件中的地址*/
    private static Long offsets = 0L;

    public static void main(String[] args) {
        System.out.println("请输入要解析的.exe文件:");
        Scanner scanner = new Scanner(System.in);
        String content = scanner.nextLine();

        File file = new File(content);

        //如果文件不存在就直接退出
        if (!file.isFile()) {
            System.out.println("文件不存在");
            return;
        }

        //填充InitialParameters中的数据
        setUp(file);
        while (true) {
            System.out.println("请输入要进行的操作,或者#号退出！");
            content = scanner.nextLine();

            /*根据输入的不同参数，做出不同的解析操作，
                #：退出
                -h: 打印整个PE头
                -i: 打印函数导入表的内容
                -e: 打印函数导出表的内容
            */
            switch (content) {
                case "#":
                    return;
                case "-h":
                    printHead(file);
                    break;
                case "-i":
                    printImportTable(file);
                    break;
                case "-e":
                    printExportTable(file);
                    break;
                default:
                    System.out.println("无效操作！");
            }
        }
    }

    /**
     * 根据要解析的PE文件，初始化{@link InitialParameters} 中的数据
     * @param file PE文件
     */
    private static void setUp(File file) {
        printHead(file);
        InitialParameters.EXPORT_TABLE_RAW = Utils.rvaToRaw(InitialParameters.EXPORT_TABLE_RVA, InitialParameters.SECTION_HEADERS);
        InitialParameters.IMPORT_TABLE_RAW = Utils.rvaToRaw(InitialParameters.IMPORT_TABLE_RVA, InitialParameters.SECTION_HEADERS);
        setUpImportTable(file);
        setUpExportTable(file);
    }

    /**
     * 打印PE头
     * @param file 目标文件
     */
    private static void printHead(File file) {
        printDosHead(file);
        printNtHead(file);
        printSectionHead(file);
    }

    /**
     * 解析Dos头
     *
     * @param file 目标文件.
     */
    private static void printDosHead(File file) {
        offsets = 0L;
        FileInputStream reader = null;
        try {
            reader = new FileInputStream(file);
            printContent(reader, "magic(魔数)", offsets, word, "\t");
            offsets = offsets + word.length;

            printContent(reader, "cblp", offsets, word, "\t");
            offsets = offsets + word.length;

            printContent(reader, "cp", offsets, word, "\t");
            offsets = offsets + word.length;

            printContent(reader, "crlc", offsets, word, "\t");
            offsets = offsets + word.length;

            printContent(reader, "cparhdr", offsets, word, "\t");
            offsets = offsets + word.length;

            printContent(reader, "minalloc", offsets, word, "\t");
            offsets = offsets + word.length;

            printContent(reader, "maxalloc", offsets, word, "\t");
            offsets = offsets + word.length;

            printContent(reader, "ss", offsets, word, "\t");
            offsets = offsets + word.length;

            printContent(reader, "sp", offsets, word, "\t");
            offsets = offsets + word.length;

            printContent(reader, "csum", offsets, word, "\t");
            offsets = offsets + word.length;

            printContent(reader, "ip", offsets, word, "\t");
            offsets = offsets + word.length;

            printContent(reader, "cs", offsets, word, "\t");
            offsets = offsets + word.length;

            printContent(reader, "lfarlc", offsets, word, "\t");
            offsets = offsets + word.length;

            printContent(reader, "ovno", offsets, word, "\t");
            offsets = offsets + word.length;


            for (int i = 0; i < 4; i++) {
                printContent(reader, "res[" + i + "]", offsets, word, "\t");
                offsets = offsets + word.length;
            }

            printContent(reader, "oemid", offsets, word, "\t");
            offsets = offsets + word.length;

            printContent(reader, "oeminfo", offsets, word, "\t");
            offsets = offsets + word.length;


            for (int i = 0; i < 10; i++) {
                printContent(reader, "res2[" + i + "]", offsets, word, "\t");
                offsets = offsets + word.length;
            }

            printContent(reader, "lfanew", offsets, word, "\t");
            InitialParameters.NT_ADDRESS = Utils.longFromBytes(word, 0);
            offsets = offsets + word.length;

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }


    /**
     * 解析NT头
     *
     * @param file 目标文件
     */
    private static void printNtHead(File file) {
        FileInputStream reader = null;
        try {
            reader = new FileInputStream(file);
            reader.skip(InitialParameters.NT_ADDRESS);
            offsets = InitialParameters.NT_ADDRESS;
            System.out.println("NT头：");

            printStringContent(reader, "Signature(PE签名)", offsets, dword, "\t", true);
            offsets = offsets + dword.length;

            System.out.println("\t文件头:");

            printContent(reader, "Machine(机器码)", offsets, word, "\t\t");
            offsets = offsets + word.length;

            printContent(reader, "NumberOfSection(节区数目)", offsets, word, "\t\t");
            InitialParameters.NUMBER_OF_SECTIONS = Utils.longFromBytes(word, 0);
            offsets = offsets + word.length;


            printContent(reader, "TimeDateStamp(时间戳)", offsets, dword, "\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "PointerToSymbolTable(符号表地址)", offsets, dword, "\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "NumberOfSymbols(符号数目)", offsets, dword, "\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "SizeOfOptionalHeader(可选头数目)", offsets, word, "\t\t");
            offsets = offsets + word.length;

            printContent(reader, "Characteristics(文件属性)", offsets, word, "\t\t");
            offsets = offsets + word.length;

            System.out.println("\t文件可选头：");

            printContent(reader, "Magic(魔数)", offsets, word, "\t\t");
            offsets = offsets + word.length;

            printContent(reader, "MajorLinkerVersion(链接器主版本号)", offsets, byteWord, "\t\t");
            offsets = offsets + byteWord.length;

            printContent(reader, "MinorLinkerVersion(链接器副版本号)", offsets, byteWord, "\t\t");
            offsets = offsets + byteWord.length;

            printContent(reader, "SizeOfCode(获取代码（文本）段的大小，或者如果有多个部分，则获取所有代码段的和)", offsets, dword, "\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "SizeOfInitializedData(已初始化数据大小)", offsets, dword, "\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "SizeOfUninitializedData(未初始化数据大小)", offsets, dword, "\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "AddressOfEntryPoint(程序开始运行的起始地址，相对于镜像首地址)", offsets, dword, "\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "BaseOfCode(内存中代码段起始地址相对于镜像首地址的偏移量)", offsets, dword, "\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "BaseOfCode(内存中数据段段起始地址相对于镜像首地址的偏移量)", offsets, dword, "\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "ImageBase(在内存中镜像首地址)", offsets, dword, "\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "SectionAlignment(节区在内存中的最小存储单位)", offsets, dword, "\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "FileAlignment(节区在文件中的最小存储单位)", offsets, dword, "\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "MajorOperatingSystemVersion(操作系统主版本号)", offsets, word, "\t\t");
            offsets = offsets + word.length;

            printContent(reader, "MinorOperatingSystemVersion(操作系统副版本号)", offsets, word, "\t\t");
            offsets = offsets + word.length;

            printContent(reader, "MajorImageVersion(程序镜像主版本号)", offsets, word, "\t\t");
            offsets = offsets + word.length;

            printContent(reader, "MinorImageVersion(程序镜像副版本号)", offsets, word, "\t\t");
            offsets = offsets + word.length;

            printContent(reader, "MajorSubSystemVersion(文件系统主版本号)", offsets, word, "\t\t");
            offsets = offsets + word.length;

            printContent(reader, "MinorSubSystemVersion(文件系统副版本号)", offsets, word, "\t\t");
            offsets = offsets + word.length;

            printContent(reader, "Win32VersionValue(Win32系统版本值)", offsets, dword, "\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "SizeOfImage(程序镜像大小)", offsets, dword, "\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "SizeOfHeaders(PE头大小)", offsets, dword, "\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "CheckSum(校验和)", offsets, dword, "\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "SubSystem(文件系统类型：驱动还是可执行文件)", offsets, word, "\t\t");
            offsets = offsets + word.length;

            printContent(reader, "DllCharacteristics(动态链接属性设置)", offsets, word, "\t\t");
            offsets = offsets + word.length;

            printContent(reader, "SizeOfStackReserve(要保留的堆栈的大小,仅提交 SizeOfStackCommit；其余部分一次提供一页，直到达到保留大小)", offsets, dword, "\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "SizeOfStackCommit(要提交的堆栈的大小)", offsets, dword, "\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "SizeOfHeapReserve(要保留的本地堆空间的大小。 仅提交 SizeOfHeapCommit；其余部分一次提供一页，直到达到保留大小))", offsets, dword, "\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "SizeOfHeapCommit(要提交的本地堆空间的大小)", offsets, dword, "\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "LoaderFlags(告知装载器是否在装载时中止和调试，或者默认地正常运行)", offsets, dword, "\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "NumberOfRvaAndSizes(DataDirectory数组大小)", offsets, dword, "\t\t");
            InitialParameters.NUMBER_OF_RVA_AND_SIZE = Utils.longFromBytes(dword, 0);
            offsets = offsets + dword.length;
            InitialParameters.SECTION_HEADER_ADDRESS = offsets + InitialParameters.NUMBER_OF_RVA_AND_SIZE * dword.length * 2;

            System.out.println("\t\tIMAGE_DATA_DIRECTORY:");

            printContent(reader, "EXPORT Directory VirtualAddress(导出表在内存中的起始地址)", offsets, dword, "\t\t\t");
            InitialParameters.EXPORT_TABLE_RVA = Utils.longFromBytes(dword, 0);
            offsets = offsets + dword.length;


            printContent(reader, "EXPORT Directory Size(导出表大小)", offsets, dword, "\t\t\t");
            InitialParameters.EXPORT_TABLE_SIZE = Utils.longFromBytes(dword, 0);
            offsets = offsets + dword.length;

            printContent(reader, "IMPORT Directory VirtualAddress(导入表在内存中的起始地址)", offsets, dword, "\t\t\t");
            InitialParameters.IMPORT_TABLE_RVA = Utils.longFromBytes(dword, 0);
            offsets = offsets + dword.length;

            printContent(reader, "IMPORT Directory Size(导入表大小)", offsets, dword, "\t\t\t");
            InitialParameters.IMPORT_TABLE_SIZE = Utils.longFromBytes(dword, 0);
            offsets = offsets + dword.length;


            printContent(reader, "RESOURCE Directory VirtualAddress", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;
            printContent(reader, "RESOURCE Directory Size", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "EXCEPTION Directory VirtualAddress", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;
            printContent(reader, "EXCEPTION Directory Size", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "SECURITY Directory VirtualAddress", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;
            printContent(reader, "SECURITY Directory Size", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "BASERELOC Directory VirtualAddress", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;
            printContent(reader, "BASERELOC Directory Size", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "DEBUG Directory VirtualAddress", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;
            printContent(reader, "DEBUG Directory Size", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "COPYRIGHT Directory VirtualAddress", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;
            printContent(reader, "COPYRIGHT Directory Size", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "GLOBALPTR Directory VirtualAddress", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;
            printContent(reader, "GLOBALPTR Directory Size", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "TLS Directory VirtualAddress", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;
            printContent(reader, "TLS Directory Size", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "LOAD_CONFIG Directory VirtualAddress", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;
            printContent(reader, "LOAD_CONFIG Directory Size", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "BOUND_IMPORT Directory VirtualAddress", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;
            printContent(reader, "BOUND_IMPORT Directory Size", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "IAT Directory VirtualAddress", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;
            printContent(reader, "IAT Directory Size", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "DELAY_IMPORT Directory VirtualAddress", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;
            printContent(reader, "DELAY_IMPORT Directory Size", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "COM_DESCRIPTOR Directory VirtualAddress", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;
            printContent(reader, "COM_DESCRIPTOR Directory Size", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;

            printContent(reader, "Reserved Directory VirtualAddress", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;
            printContent(reader, "Reserved Directory Size", offsets, dword, "\t\t\t");
            offsets = offsets + dword.length;

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

    }

    /**
     * 解析节区头
     *
     * @param file 目标文件
     */
    private static void printSectionHead(File file) {
        FileInputStream reader = null;
        try {
            reader = new FileInputStream(file);
            System.out.println("节区头：");
            reader.skip(InitialParameters.SECTION_HEADER_ADDRESS);
            offsets = InitialParameters.SECTION_HEADER_ADDRESS;
            for (int i = 0; i < InitialParameters.NUMBER_OF_SECTIONS; i++) {
                SectionHeader sectionHeader = new SectionHeader();

                System.out.println();
                printStringContent(reader, "Name(名字)", offsets, longWord, "\t", true);
                sectionHeader.name = new String(longWord);
                offsets += longWord.length;

                printContent(reader, "VirtualSize(内存中节区所占大小)", offsets, dword, "\t");
                sectionHeader.virtualSize = Utils.longFromBytes(dword, 0);
                offsets += dword.length;

                printContent(reader, "VirtualAddress(内存中节区起始地址RVA)", offsets, dword, "\t");
                sectionHeader.virtualAddress = Utils.longFromBytes(dword, 0);
                offsets += dword.length;

                printContent(reader, "SizeOfRawData(磁盘文件中节区所占大小)", offsets, dword, "\t");
                sectionHeader.sizeOfRawData = Utils.longFromBytes(dword, 0);
                offsets += dword.length;

                printContent(reader, "PointerToRawData(磁盘文件中节区数据的起始位置)", offsets, dword, "\t");
                sectionHeader.pointerToRawData = Utils.longFromBytes(dword, 0);
                offsets += dword.length;

                printContent(reader, "PointerToRelocation(重定位表起始位置)", offsets, dword, "\t");
                offsets += dword.length;

                printContent(reader, "PointerToLinenumbers", offsets, dword, "\t");
                offsets += dword.length;

                printContent(reader, "NumberOfRelocations(重定位表项数)", offsets, word, "\t");
                offsets += word.length;

                printContent(reader, "NumberOfLinenumbers", offsets, word, "\t");
                offsets += word.length;

                printContent(reader, "Characteristics(节区属性)", offsets, dword, "\t");
                offsets += dword.length;
                InitialParameters.SECTION_HEADERS.add(sectionHeader);
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

    }

    /**
     * 根据目标文件，初始化导入函数表
     * @param file 目标文件
     */
    private static void setUpImportTable(File file) {
        RandomAccessFile reader = null;
        try {
            reader = new RandomAccessFile(file, "r");

            //将文件指针定位到导入函数表首地址
            reader.seek(InitialParameters.IMPORT_TABLE_RAW);

            byte[] descriptor = new byte[Constant.IMPORT_DESCRIPTOR];
            reader.read(descriptor);

            //循环读取描述符，直到读取的数据全为0
            while (Utils.hasText(new String(descriptor))) {
                InitialParameters.IMPORT_TABLE.add(new ImportDescriptor(descriptor));
                reader.read(descriptor);
            }

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * 根据目标文件，初始化导出函数表
     * @param file 目标文件
     */
    public static void setUpExportTable(File file){
        RandomAccessFile reader = null;
        try {
            reader = new RandomAccessFile(file, "r");

            //将文件指针定位到导出函数表首地址
            reader.seek(InitialParameters.EXPORT_TABLE_RAW);

            byte[] descriptor = new byte[Constant.EXPORT_DESCRIPTOR];
            reader.read(descriptor);

            InitialParameters.EXPORT_TABLE = new ExportDescriptor(descriptor);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    /**
     * 输出数据
     *
     * @param reader      读取的文件
     * @param description 数据的对应描述
     * @param offset      数据的起始位置
     * @param content     装载数据的字节数组
     * @param begin       输出内容最开始的占位符
     * @throws IOException 读取数据IO错误
     */
    private static void printContent(FileInputStream reader, String description, Long offset, byte[] content, String begin) throws IOException {
        printStringContent(reader, description, offset, content, begin, false);
    }

    private static void printStringContent(FileInputStream reader, String description, Long offset, byte[] content, String begin, boolean isString) throws IOException {
        StringBuilder builder = new StringBuilder();
        reader.read(content);
        if (isString) {
            builder.append(begin).append(Long.toHexString(offset).toUpperCase())
                    .append("\t\t").append(bytesToHex3(content)).append("\t").
                    append(description).append("(").append(new String(content)).
                    append(")");
        } else {
            Utils.reverseByteArray(content);
            builder.append(begin).append(Long.toHexString(offset).toUpperCase())
                    .append("\t\t").append(bytesToHex3(content)).append("\t").
                    append(description);
        }
        System.out.println(builder.toString());
    }

    /**
     * 打印目标文件中所有的导出函数
     * @param file 目标文件
     */
    private static void printExportTable(File file){
        RandomAccessFile reader = null;

        try {

            reader = new RandomAccessFile(file,"r");
            //打印导出库名称
            System.out.println(Utils.getString(InitialParameters.EXPORT_TABLE.nameRaw, reader) + ": ");

            //获取出库中所有导出函数
            List<ExportItem> items = InitialParameters.EXPORT_TABLE.getExportTable(reader);
            for (ExportItem item : items) {
                System.out.println("\t" + item.toString());
            }
        } catch (IOException e) {
            e.printStackTrace();
        }finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

    }

    /**
     * 打印目标文件中所有的导入函数
     * @param file 目标文件
     */
    private static void printImportTable(File file) {
        RandomAccessFile reader = null;
        try {
            reader = new RandomAccessFile(file, "r");
            for (ImportDescriptor descriptor : InitialParameters.IMPORT_TABLE) {
                //打印导入库名称
                System.out.println(Utils.getString(descriptor.nameRaw, reader) + ": ");

                //获取导入库中被导入的函数
                List<ImportItem> items = descriptor.getImportTable(reader);
                for (ImportItem item : items) {
                    System.out.println("\t" + item.toString());
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

    }

    /**
     * 将字节数组以16进制字符串格式输出
     * @param bytes 字节数组
     * @return 16进制字符串
     */
    private static String bytesToHex3(byte[] bytes) {
        StringBuilder buf = new StringBuilder(bytes.length * 2);
        // 使用String的format方法进行转换
        for (byte b : bytes) {
            buf.append(String.format("%02x", b & 0xff));
        }
        return buf.toString();
    }





//C:\Users\CodeGang\Desktop\书上示列\角嚼抗力\02_PE_File_Format\13_PE_File_Format\bin\notepad.exe
//C:\Users\CodeGang\Desktop\书上示列\角嚼抗力\02_PE_File_Format\13_PE_File_Format\bin\kernel32.dll
}
