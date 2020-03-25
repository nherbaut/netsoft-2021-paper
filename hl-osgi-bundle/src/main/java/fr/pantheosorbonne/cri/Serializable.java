package fr.pantheosorbonne.cri;

public interface Serializable {

    byte[] dump();

    void load(byte[] data);

    String[] getArgs();

}