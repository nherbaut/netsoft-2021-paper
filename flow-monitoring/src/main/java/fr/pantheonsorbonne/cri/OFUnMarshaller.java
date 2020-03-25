package fr.pantheonsorbonne.cri;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;

import javax.management.RuntimeErrorException;

public class OFUnMarshaller {

    @SuppressWarnings("unchecked")
    public static <T> T unMarshall(Class<T> c, String[] args) {
        T t;
        try {
            t = (T) c.getConstructors()[0].newInstance(null);

            Field[] fields = c.getDeclaredFields();
            for (Field field : fields) {
                for (String arg : args) {
                    if (arg.contains(field.getName() + "=")) {

                        if (field.getType().equals(String.class) || field.getType().equals(Integer.TYPE)) {
                            int indexStart = arg.indexOf(field.getName() + "=") + field.getName().length() + 1;
                            int indexStop = arg.indexOf(",", indexStart + 1);
                            indexStop = indexStop == -1 ? arg.length() : indexStop;
                            try {

                                if (field.getType().equals(String.class)) {
                                    field.set(t, arg.substring(indexStart, indexStop));
                                } else {

                                    field.set(t, Integer.parseInt(arg.substring(indexStart, indexStop)));
                                }
                                break;
                            } catch (IllegalArgumentException | IllegalAccessException e) {

                                e.printStackTrace();
                            }

                        } else if (field.getType().equals(Boolean.TYPE)) {
                            try {
                                field.set(t, true);
                            } catch (IllegalArgumentException | IllegalAccessException e) {
                                e.printStackTrace();
                            }

                        }

                    }
                }
            }
            return t;
        } catch (InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException
                | SecurityException e1) {

            throw new RuntimeException(e1);
        }
    }

}
