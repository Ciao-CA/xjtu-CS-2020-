clc
clear
close
s0=textread('start.txt');
target=[1 2 3;8 0 4;7 6 5];
open={s0};
father={s0};
node=0;
n=0;
count=1;
while(1)
    close=[];
    close=open(1);
    open(1)=[];
    n=n+1;
    if close{1}==target;
        close{1}
        "The search tree has been found, it is printing now"
        break
    else
        y=extend(close{1});
        yy=cellxor(y,father);
        father=[father,yy];
        node(count+1:count+size(yy,2))=n;
        count=count+size(yy,2);
        open=[open yy];
    end
end
cm=zeros(n,n);
for i=2:n
    cm(node(i),i)=1;
end
for i=1:n
temp=father{i};
temp=temp';
num(i,:)=temp(:);
id{i}=[num2str(num(i,1:3)) ' # ' num2str(num(i,4:6)) ' # ' num2str(num(i,7:9))];
end    
bg=biograph(cm,id);
view(bg)