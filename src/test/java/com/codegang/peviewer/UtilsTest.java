package com.codegang.peviewer;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.List;

class UtilsTest {
    public static File PE = null;

    @BeforeAll
    static void setUp(){
        PE=new File("./src/test/resources/kernel32.dll");
    }

    @Test
    void loadValue() {
        long expected =9460301L;
        RandomAccessFile reader = null;
        try {
            reader=new RandomAccessFile(PE,"r");

            long actual = Utils.loadValue(reader,new byte[4]);

            Assertions.assertEquals(expected,actual);
        } catch (IOException e){
            e.printStackTrace();
        }finally {
            if(reader!=null){
                try {
                    reader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    @Test
    void longFromBytes() {
        long expected = 3081L;
        byte[] tmp = {0,0,12,9};
        long actual = Utils.longFromBytes(tmp,0);
        Assertions.assertEquals(expected,actual);
    }

    @Test
    void longFromBytes1() {
        long expected = 12L;
        byte[] tmp = {0,0,12,9};
        long actual = Utils.longFromBytes(tmp,0,3);
        Assertions.assertEquals(expected,actual);
    }

    @Test
    void reverseByteArray() {
        byte[] expected = {4,3,2,1};
        byte[] actual = {1,2,3,4};
        Utils.reverseByteArray(actual);

        Assertions.assertArrayEquals(expected,actual);
    }

    @Test
    void getString() {
        long raw =16270L;
        String expected = "KERNEL32.dll";
        RandomAccessFile reader = null;
        try {
            reader=new RandomAccessFile(PE,"r");
            String actual = Utils.getString(raw,reader);

            Assertions.assertEquals(expected,actual);
        } catch (IOException e){
            e.printStackTrace();
        }finally {
            if(reader!=null){
                try {
                    reader.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }


    @Test
    void rvaToRaw() {
        List<SectionHeader> list= new ArrayList<>();
        SectionHeader header = new SectionHeader();
        header.virtualAddress=4096;
        header.pointerToRawData=1024;
        header.virtualSize=53677;
        header.sizeOfRawData=537088;
        header.name="test";

        list.add(header);

        long rva = 9772;
        long expected = 6700;
        long actual = Utils.rvaToRaw(rva,list);
        Assertions.assertEquals(expected,actual);

        expected = -1;
        rva = 10;
        actual = Utils.rvaToRaw(rva,list);
        Assertions.assertEquals(expected,actual);
    }

    @Test
    void hasText() {
        String s ="    ";
        Assertions.assertFalse(Utils.hasText(s));

        s="123";
        Assertions.assertTrue(Utils.hasText(s));

        s=null;
        Assertions.assertFalse(Utils.hasText(s));

        s="\t";
        Assertions.assertFalse(Utils.hasText(s));
    }

    @Test
    void hasData() {
        byte[] s = {'\t'};
        Assertions.assertTrue(Utils.hasData(s));

        s[0]='\0';
        Assertions.assertFalse(Utils.hasData(s));

        byte[] s2 = {0,0,0,0,0,0,0};
        Assertions.assertFalse(Utils.hasData(s2));

        s2[0]='\0';
        Assertions.assertFalse(Utils.hasData(s2));

        s2[0]='\t';
        Assertions.assertTrue(Utils.hasData(s2));
    }
}