clear
clc
close
prompt='please input P(E)  ';
pe=input(prompt);
prompt='please input P(H)  ';
ph=input(prompt);
prompt='please input LS  ';
ls=input(prompt);
prompt='please input LN  ';
ln=input(prompt);
ph_ne=ph*ln/(1-ph+ph*ln);
ph_e=ph*ls/(1+ph*(ls-1));
pe_s=0:0.001:1;
n=size(pe_s,2);
for i=1:n
    if(pe_s(i)<=pe)   ph_s(i)=ph_ne+(ph-ph_ne)/pe*pe_s(i);
    else ph_s(i)=ph+(ph_e-ph)/(1-ph)*(pe_s(i)-pe);
    end
end
plot(pe_s,ph_s,'linewidth',2)
grid on
hold on
plot(pe,ph,'*','markersize',8)
xlabel('P(E/S)')
ylabel('P(H/S)')
set(gca,'fontsize',13)